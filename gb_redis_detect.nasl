# Copyright (C) 2013 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103844");
  script_version("2022-10-17T11:13:19+0000");
  script_tag(name:"last_modification", value:"2022-10-17 11:13:19 +0000 (Mon, 17 Oct 2022)");
  script_tag(name:"creation_date", value:"2013-12-02 13:58:18 +0100 (Mon, 02 Dec 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Redis Server Detection");

  script_category(ACT_GATHER_INFO);

  script_family("Product detection");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service1.nasl");
  script_require_ports("Services/redis", 6379);

  script_tag(name:"summary", value:"Remote detection of Redis server.");

  script_xref(name:"URL", value:"https://redis.io/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("misc_func.inc");
include("port_service_func.inc");

cpe_base = "cpe:/a:redis:redis";
app = "Redis Server";
install = "/";
version = "unknown";

port = service_get_port( default:6379, proto:"redis" );

soc = open_sock_tcp( port );
if( ! soc )
  exit( 0 );

send( socket:soc, data:'PING\r\n' );
recv = recv( socket:soc, length:32 );

if( recv =~ "^\-NOAUTH" ) {
  send( socket:soc, data:'AUTH foobared\r\n' );
  recv = recv( socket:soc, length:128 );

  if( "-ERR invalid password" >< recv ) {
    close( soc );
    set_kb_item( name:"redis/installed", value:TRUE );

    service_register( port:port, proto:"redis" );

    register_product( cpe:cpe_base, location:install, port:port, service:"redis" );

    log_message( data:build_detection_report( app:app, version:version, install:install, cpe:cpe_base,
                                              concluded:recv,
                                              extra:"The Redis server is protected by a password." ),
                 port:port );
    exit( 0 );
  } else if( "-WRONGPASS invalid username-password pair or user is disabled." >< recv ) {
    close( soc );
    set_kb_item( name:"redis/installed", value:TRUE );

    service_register( port:port, proto:"redis" );

    register_product( cpe:cpe_base, location:install, port:port, service:"redis" );

    log_message( data:build_detection_report( app:app, version:version, install:install, cpe:cpe_base,
                                              concluded:recv,
                                              extra:"The default user is disabled and uses a password" +
                                              " or the default user is enabled and uses a non default password." +
                                              " This indicates that Redis 6 or newer is used." ),
                 port:port );
    exit( 0 );
  } else if( "-ERR AUTH <password> called without any password configured for the default user. " +
             "Are you sure your configuration is correct?" >< recv ) {
    close( soc );
    set_kb_item( name:"redis/installed", value:TRUE );

    service_register( port:port, proto:"redis" );

    register_product( cpe:cpe_base, location:install, port:port, service:"redis" );

    log_message( data:build_detection_report( app:app, version:version, install:install, cpe:cpe_base,
                                              concluded:recv,
                                              extra:"The default user of the Redis server is disabled and no password is set." +
                                              " This indicates that Redis 6 or newer is used." ),
                 port:port );
    exit( 0 );
  }

  set_kb_item( name:"redis/" + port + "/default_password", value:TRUE );
  set_kb_item( name:"redis/default_password", value:TRUE );

  extra = "Redis Server is protected with the default password 'foobared'.";
}

else if( "-DENIED Redis is running in prot" >< recv ) { # nb: The 32 byte length from above...
  close( soc );

  set_kb_item( name:"redis/installed", value:TRUE );

  service_register( port:port, proto:"redis" );

  log_message( data:build_detection_report( app:app, version:version, install:install, cpe:cpe_base,
                                            concluded:recv,
                                            extra:"The Redis server is running in protected mode." ),
               port:port );

  set_kb_item( name:"redis/" + port + "/protected_mode", value:TRUE );
  set_kb_item( name:"redis/protected_mode", value:TRUE );

  exit( 0 );
}

else if( recv =~ "^\+?PONG" || "-MISCONF Redis is configured to " >< recv ) { # nb: The 32 byte length from above...

  # If the MISCONF is showing up we still can gather the info that the server is unprotected
  # but we need to receive more data before the AUTH below...
  if( "-MISCONF Redis is configured to" >< recv )
    recv_line( socket:soc, length:2048 );

  vt_strings = get_vt_strings();

  send( socket:soc, data:'AUTH ' + vt_strings["lowercase"] + '\r\n' );
  recv = recv( socket:soc, length:128 );
  if( "-ERR Client sent AUTH, but no password is set" >< recv ||
      "-ERR AUTH <password> called without any password configured for the default user. " +
      "Are you sure your configuration is correct?" >< recv ) {
    set_kb_item( name:"redis/" + port + "/no_password", value:TRUE );
    set_kb_item( name:"redis/no_password", value:TRUE );
    extra = "Redis Server is not protected with a password.";
  }
}

send( socket:soc, data:'info\r\n' );
recv = recv( socket:soc, length:1024 );
close( soc );

if( "redis_version" >!< recv )
  exit( 0 );

set_kb_item( name:"redis/installed", value:TRUE );

vers = eregmatch( pattern:'redis_version:([^\r\n]+)', string:recv );
if( ! isnull( vers[1] ) ) {
  version = vers[1];
  set_kb_item( name:"redis/" + port + "/version", value:version );
}

cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:cpe_base + ":" );
if( ! cpe )
  cpe = cpe_base;

service_register( port:port, proto:"redis" );

register_product( cpe:cpe, location:install, port:port, service:"redis" );

log_message( data:build_detection_report( app:app, version:version, install:install, cpe:cpe,
                                          concluded:vers[0],  extra:extra ),
             port:port );

exit( 0 );

# Copyright (C) 2017 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140129");
  script_version("2022-07-07T10:16:06+0000");
  script_tag(name:"last_modification", value:"2022-07-07 10:16:06 +0000 (Thu, 07 Jul 2022)");
  script_tag(name:"creation_date", value:"2017-01-27 09:57:51 +0100 (Fri, 27 Jan 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Sybase TCP/IP Listener Detection");

  script_category(ACT_GATHER_INFO);

  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "mssqlserver_detect.nasl", "oracle_tnslsnr_version.nasl");
  script_require_ports("Services/unknown", 5000);

  script_tag(name:"summary", value:"Detects a Sybase TCP/IP listener server by sending a login
  packet and checking the response.");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("sybase_func.inc");

port = unknownservice_get_port( default:5000 );

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

vt_strings = get_vt_strings();
creds = vt_strings["default"];

sql_packet = make_sql_login_pkt( username:creds, password:creds );

send( socket:soc, data:sql_packet );
send( socket:soc, data:pkt_lang );

buf = recv( socket:soc, length:255 );

close( soc );

if( "Login failed" >< buf ) {
  set_kb_item( name:"sybase/tcp_listener/detected", value:TRUE );
  set_kb_item( name:"sybase/tcp_listener/" + port + "/detected", value:TRUE );

  cpe = "cpe:/a:sybase:adaptive_server_enterprise";

  register_product( cpe:cpe, location:"/", port:port, service:"sybase_tcp_listener" );
  service_register( proto:"sybase", port:port );

  log_message( data:build_detection_report( app:"Sybase TCP/IP listener", install:"/", cpe:cpe,
                                            skip_version:TRUE ),
               port:port );
  exit( 0 );
}

exit( 0 );

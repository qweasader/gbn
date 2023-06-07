###############################################################################
# OpenVAS Vulnerability Test
#
# ZNC Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100243");
  script_version("2020-11-10T15:30:28+0000");
  script_tag(name:"last_modification", value:"2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)");
  script_tag(name:"creation_date", value:"2009-07-26 19:54:54 +0200 (Sun, 26 Jul 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ZNC Detection (IRC)");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "find_service1.nasl", "find_service2.nasl", "gb_znc_http_detect.nasl");
  script_require_ports("Services/irc", "Services/www", 6667, 6697);

  script_tag(name:"summary", value:"IRC based detection ZNC.");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

ports = make_list();
irc_ports = service_get_ports( default_port_list:make_list( 6667, 6697 ), proto:"irc" );
if( irc_ports )
  ports = make_list( ports, irc_ports );

# nb: On ZNC the same port can provide the IRC and HTTP service but the find_service*.nasl
# are marking the service only as "www". As the port is:
#
# - often changed by the user because 6667 isn't allowed to be accessed by most common browsers
# - find_service*.nasl are not detecting the IRC service in most cases because the service isn't
#   responding to the request done by that VT or it is only detected as "www"
#
# we need to check all previously detected "www" services as well. To avoid that we're sending
# the "USER" request below to every HTTP service we rely on a previous HTTP detection of ZNC.
#
# There is another case we need to check for the HTTP ports as well which is a disabled Web Access.
# In this case the service is responding with something like e.g. which is still detected (correctly)
# by find_service*.nasl as a HTTP service:
#
# HTTP/1.0 403 Access Denied
#
#
# Web Access is not enabled.
#
# For this kind of response we also want to send the USER request below.
#
# nb: Don't use http_get_ports because we want to check the IRC service even if the HTTP service
#     is marked as e.g. "broken" or CGI scanning is disabled.
#
http_ports = service_get_ports( default_port_list:make_list( 6667, 6697 ), proto:"www" );
if( http_ports ) {
  foreach http_port( http_ports ) {

    res = http_get_cache( port:http_port, item:"/" );

    if( ! get_kb_item( "znc/http/" + http_port + "/detected" ) &&
        "Web Access is not enabled" >!< res )
      continue;

    ports = make_list( ports, http_port );
  }
}

ports = make_list_unique( ports );

foreach port( ports ) {
  soc = open_sock_tcp( port );
  if( ! soc )
    continue;

  req = string( "USER\r\n" );
  send( socket:soc, data:req );

  buf = recv_line( socket:soc, length:64 );
  close( soc );

  if( egrep( pattern:"irc\.znc\.in NOTICE AUTH", string:buf, icase:TRUE ) ||
      ( "irc.znc.in" >< buf && "Password required" >< buf ) ) {
    version = "unknown";

    # nb: If the service was detected as "www" we need to register it as "irc" again.
    service_register( port:port, proto:"irc", message:"An IRC server seems to be running on this port." );

    set_kb_item( name:"znc/detected", value:TRUE );
    set_kb_item( name:"znc/irc/detected", value:TRUE );
    set_kb_item( name:"znc/irc/port", value:port );
    set_kb_item( name:"znc/irc/" + port + "/detected", value:TRUE );
    set_kb_item( name:"znc/irc/" + port + "/version", value:version );
    set_kb_item( name:"znc/irc/" + port + "/concluded", value:chomp( buf ) );
  }
}

exit( 0 );

###############################################################################
# OpenVAS Vulnerability Test
#
# Booked Scheduler Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105259");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2021-09-07T06:04:54+0000");
  script_tag(name:"last_modification", value:"2021-09-07 06:04:54 +0000 (Tue, 07 Sep 2021)");
  script_tag(name:"creation_date", value:"2015-04-20 14:04:38 +0200 (Mon, 20 Apr 2015)");
  script_name("Booked Scheduler Detection");

  script_tag(name:"summary", value:"The script sends a connection
 request to the server and attempts to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_active");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/booked", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";
  url = dir + "/Web/?";
  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req );
  if( buf == NULL ) continue;

  if( egrep( pattern: "Booked - Log In", string: buf, icase: TRUE ) && "Booked Scheduler" >< buf )
  {
    vers = "unknown";
    version = eregmatch( string: buf, pattern: "Booked Scheduler v([0-9.]+)",icase:TRUE );

    if ( ! isnull( version[1] ) ) vers = chomp( version[1] );

    set_kb_item(name:"booked_scheduler/installed",value:TRUE);

    cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:twinkle_toes:booked_scheduler:" );
    if( isnull( cpe ) ) cpe = "cpe:/a:twinkle_toes:booked_scheduler";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data: build_detection_report( app:"Booked Scheduler",
                                               version:vers,
                                               install:install,
                                               cpe:cpe,
                                               concluded: version[0] ),
                 port:port );
  }
}

exit(0);

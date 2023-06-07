###############################################################################
# OpenVAS Vulnerability Test
#
# Sangoma NetBorder/Vega Session Controller Detection
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112183");
  script_version("2021-04-15T13:23:31+0000");
  script_tag(name:"last_modification", value:"2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)");
  script_tag(name:"creation_date", value:"2018-01-11 12:07:00 +0100 (Thu, 11 Jan 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Sangoma NetBorder/Vega Session Controller Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.sangoma.com/products/sbc/");

  script_tag(name:"summary", value:"This script sends an HTTP GET request to figure out whether a
  web-based service of Sangoma Session Border Controller (SBC) is running on the target host, and,
  if so, which version is installed.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

hw_cpe = "cpe:/h:sangoma:netborder%2fvega_session";
hw_name = "Sangoma NetBorder/Vega Session Controller";
os_cpe = "cpe:/o:sangoma:netborder%2fvega_session_firmware";
os_name = hw_name + " Firmware";

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  installed = FALSE;
  install = dir;
  if( dir == "/" ) dir = "";

  foreach file( make_list( "/", "/index.php" ) ) {

    url = dir + file;
    res = http_get_cache( item:url, port:port );

    if( "Session Controller" >< res && 'SNG_logo.png" alt="Sangoma"' >< res ) {
      installed = TRUE;
      break;
    }
  }

  if( installed ) {

    set_kb_item( name:"sangoma/nsc/detected", value:TRUE );
    version = "unknown";

    os_register_and_report( os:os_name, cpe:os_cpe, desc:"Sangoma NetBorder/Vega Session Controller Detection", runs_key:"unixoide" );

    register_product( cpe:os_cpe, location:install, port:port, service:"www" );
    register_product( cpe:hw_cpe, location:install, port:port, service:"www" );

    report  = build_detection_report( app:os_name, version:version, install:install, cpe:os_cpe );
    report += '\n\n';
    report += build_detection_report( app:hw_name, install:install, cpe:hw_cpe, skip_version:TRUE );

    log_message( port:port, data:report );
  }
}

exit( 0 );

###############################################################################
# OpenVAS Vulnerability Test
#
# Kerio WinRoute Firewall HTTP/HTTPS Management Detection
#
# Authors:
# Ferdy Riphagen <f[dot]riphagen[at]nsec[dot]nl>
# Changes by Tenable :
#  - Improved version extraction
#  - Report layout
#  - Fixed SSL detection
#
# Copyright:
# Copyright (C) 2006 Ferdy Riphagen
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.20225");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Kerio WinRoute Firewall HTTP/HTTPS Management Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2006 Ferdy Riphagen");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 4080, 4081);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The remote host appears to be running the Kerio WinRoute Firewall
  application. It is possible to access the HTTP or HTTPS management interface on the host.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:4080 );

res = http_get_cache( item:"/", port:port );
if( ! res ) exit( 0 );

if( "Kerio WinRoute Firewall" >< res && line = egrep( pattern:"Kerio WinRoute Firewall [0-9.]+", string:res ) ) {

  version = ereg_replace( pattern:".*Kerio WinRoute Firewall ([0-9.]+).*", string:line, replace:"\1" );
  if( version == line )
    version = "unknown";

  if( version != "unknown" )
    set_kb_item( name:"www/" + port + "/kerio_wrf", value:version );

  register_and_report_cpe( app:"Kerio WinRoute Firewall Management Webserver", ver:version, concluded:line, regService:"www", regPort:port, base:"cpe:/a:kerio:winroute_firewall:", expr:"^([0-9.]+)", insloc:"/" );
}

exit( 0 );

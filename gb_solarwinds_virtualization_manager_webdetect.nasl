###############################################################################
# OpenVAS Vulnerability Test
#
# SolarWinds Virtualization Manager Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105766");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2016-06-15 21:09:20 +0200 (Wed, 15 Jun 2016)");
  script_name("SolarWinds Virtualization Manager Detection");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:80 );

url = '/swvm/ConsoleContainer.jsp';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "<title>SolarWinds Virtualization Manager</title>" >!< buf ) exit( 0 );

cpe = 'cpe:/a:solarwinds:virtualization_manager';
vers = 'unknown';

set_kb_item( name:"solarwinds/virtualization_manager/installed", value:TRUE );

# ConsoleContainer.swf?version=6.3.1.575
# ConsoleContainer.swf?version=6.3.2.69
version = eregmatch( pattern:'src="ConsoleContainer.swf\\?version=([0-9.]+[^"]+)"', string:buf );
if( ! isnull( version[1] ) )
{
  parts = split( version[1], sep:".", keep:FALSE );

  vers = parts[0] + '.' + parts[1] + '.' + parts[2];
  rep_vers = vers;

  if( parts[3] )
  {
    build = parts[3];
    set_kb_item( name:"solarwinds/virtualization_manager/build", value:build );
    rep_vers += ' Build ' + build;
  }

  set_kb_item( name:"solarwinds/virtualization_manager/version", value:vers );
}

register_product( cpe:cpe, location:"/swvm/", port:port, service:'www' );

report = build_detection_report( app:"SolarWinds Virtualization Manager", version:rep_vers, install:"/swvm/", cpe:cpe, concluded:version[0] );
log_message( port:port, data:report );
exit( 0 );


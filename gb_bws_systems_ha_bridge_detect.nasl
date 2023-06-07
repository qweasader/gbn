###############################################################################
# OpenVAS Vulnerability Test
#
# BWS Systems HA-Bridge Remote Detection
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813626");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-07-03 12:16:33 +0530 (Tue, 03 Jul 2018)");
  script_name("BWS Systems HA-Bridge Remote Detection");

  script_tag(name:"summary", value:"Detection of BWS Systems HA-Bridge.

  The script sends a HTTP connection request to the remote host and
  attempts to detect if the remote host is BWS Systems HA-Bridge.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

bwsPort = http_get_port(default:80);

res = http_get_cache(item:"/", port:bwsPort);
if( "<title>HA Bridge</title>" >< res && ">Developed by BWS Systems" >< res ) {

  version = "unknown";
  set_kb_item( name:"BWSSystems/HA/Bridge/installed", value:TRUE );
  cpe = 'cpe:/h:bws_systems:ha_bridge';

  register_product( cpe:cpe, port:bwsPort, location:"/", service:"www" );
  log_message( data:build_detection_report( app:"BWS Systems HA Bridge",
                                            version:version,
                                            install:"/",
                                            cpe:cpe,
                                            concluded:version ),
                                            port:bwsPort );
  exit(0);
}
exit(0);

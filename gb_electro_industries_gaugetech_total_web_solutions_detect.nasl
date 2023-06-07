###############################################################################
# OpenVAS Vulnerability Test
#
# Electro Industries GaugeTech Total Web Solutions Remote Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.813628");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-07-04 11:28:37 +0530 (Wed, 04 Jul 2018)");
  script_name("Electro Industries GaugeTech Total Web Solutions Remote Detection");

  script_tag(name:"summary", value:"Detection of Electro Industries GaugeTech
  Total Web Solutions.

  The script sends a connection request to the remote host and attempts to detect
  if the remote host is Electro Industries GaugeTech Total Web Solutions.");

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

elePort = http_get_port(default:80);

res = http_get_cache(item:"/", port:elePort);

if(res =~ "^HTTP/1\.[01] 200" && "<title>Total Web Solutions</title>" >< res &&
   "Server: EIG Embedded Web Server" >< res)
{
  res = http_get_cache(item:"/voltage.htm", port:elePort);

  if("powered by Electro Industries GaugeTech" >< res)
  {
    version = "unknown";

    set_kb_item( name:"ElectroIndustries/GaugeTech/TotalWebSolutions/installed", value:TRUE );

    ## Created new cpe
    cpe = 'cpe:/h:electroindustries_gaugetech:total_websolutions';

    register_product( cpe:cpe, port:elePort, location:"/", service:"www");
    log_message( data:build_detection_report( app:"Electro Industries GaugeTech Total Web Solutions",
                                              version:version,
                                              install:"/",
                                              cpe:cpe,
                                              concluded:version),
                                              port:elePort );
    exit(0);
  }
}
exit(0);

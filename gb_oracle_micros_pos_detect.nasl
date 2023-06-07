###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle MICROS POS Remote Detection
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.812690");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-02-02 14:53:57 +0530 (Fri, 02 Feb 2018)");
  script_name("Oracle MICROS POS Remote Detection");

  script_tag(name:"summary", value:"Detection of running version of
  Oracle Micros POS system.

  This script sends an HTTP GET request and tries to ensure the presence of
  Oracle Micros POS system.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

posPort = http_get_port(default:8080);
res = http_get_cache(item:"/", port:posPort);

if(res =~ "Server: mCommerceMobileWebServer" && (">Simphony Mobile Web Server<" >< res ||
             ">MICROS Simphony<" >< res))
{
  version = "unknown";

  set_kb_item(name:"Oracle/Micros/POS/Detected", value:TRUE);

  cpe = "cpe:/a:oracle:hospitality_simphony";

  register_product(cpe:cpe, location:"/", port:posPort, service:"www");

  log_message(data:build_detection_report(app:"Oracle MICROS POS System",
                                          version:version,
                                          install:"/",
                                          cpe:cpe,
                                          concluded:version),
                                          port:posPort);
  exit(0);
}
exit(0);

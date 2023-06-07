###############################################################################
# OpenVAS Vulnerability Test
#
# WiseGiga NAS Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.811320");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2017-09-12 13:01:23 +0530 (Tue, 12 Sep 2017)");
  script_name("WiseGiga NAS Detection");

  script_tag(name:"summary", value:"Detection of WiseGiga NAS Device(s).

  The script sends a connection request to the server and attempts to
  detect the presence of WiseGiga NAS Device(s).");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

netPort = http_get_port(default:80);

res = http_get_cache(port: netPort, item: "/");

if("<title>WISEGIGA</title>" >< res && "/webfolder/</a><br" >< res) {
  version = "unknown";

  set_kb_item(name:"WiseGiga_NAS/detected", value: TRUE);

  cpe = "cpe:/h:wisegiga:nas";

  register_product(cpe:cpe, location:"/", port:netPort, service:"www");

  log_message(data: build_detection_report(app: "WiseGiga NAS Device",
                                           version: version,
                                           install: "/",
                                           cpe: cpe),
              port: netPort);
  exit(0);
}

exit(0);

# OpenVAS Vulnerability Test
# Description: Symantec Web Security Detection
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2008 David Maciejak
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80019");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2008-10-24 19:51:47 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Symantec Web Security Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 David Maciejak");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("SWS/banner");
  script_require_ports("Services/www", 8002);

  script_tag(name:"summary", value:"The remote web server appears to be running Symantec Web Security,
  for filtering traffic of viruses and inappropriate content.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port(default:8002);
banner = http_get_remote_headers(port:port);

if(banner && "erver: SWS-" >< banner) {

  version = "unknown";

  ver = strstr(banner, "Server: SWS-") - "Server: SWS-";
  if(ver)
    ver = ver - strstr(ver, '\r');

  if(ver)
    ver = ver - strstr(ver, '\n');

  if(ver && ver =~ "^[0-9]")
    version = string(ver);

  set_kb_item(name:"www/" + port + "/SWS", value:version);
  set_kb_item(name:"SymantecWS/installed", value:TRUE);

  cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:symantec:web_security:");
  if(!cpe)
    cpe = "cpe:/a:symantec:web_security";

  register_product(cpe:cpe, location:"/", port:port, service:"www");

  log_message(data:build_detection_report(app:"Symantec Web Security", version:version, install:"/", cpe:cpe, concluded:version),
              port:port);

}

###############################################################################
# OpenVAS Vulnerability Test
#
# Master IP Camera Remote Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.812657");
  script_version("2020-02-03T13:52:45+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-02-03 13:52:45 +0000 (Mon, 03 Feb 2020)");
  script_tag(name:"creation_date", value:"2018-01-22 12:19:43 +0530 (Mon, 22 Jan 2018)");
  script_name("Master IP Camera Remote Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_thttpd_detect.nasl");
  script_mandatory_keys("thttpd/detected");

  script_tag(name:"summary", value:"This script tries to detect a Master IP Camera
  and its version.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

thttpd_CPE = "cpe:/a:acme:thttpd";

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:thttpd_CPE))
  exit(0);

res = http_get_cache(item:"/web/index.html", port:port);

if(("<title>ipCAM<" >< res || "<title>Camera<" >< res) && "cgi-bin/hi3510" >< res && ">OCX" >< res) {

  version = "unknown";
  set_kb_item(name:"MasterIP/Camera/Detected", value:TRUE);

  cpe = "cpe:/h:masterip:masterip_camera";

  register_product(cpe:cpe, location:"/", port:port, service:"www");

  log_message(data:build_detection_report(app:"Master IP Camera",
                                          version:version,
                                          install:"/",
                                          cpe:cpe),
                                          port:port);
}

exit(0);

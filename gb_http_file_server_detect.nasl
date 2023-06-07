###############################################################################
# OpenVAS Vulnerability Test
#
# Http File Server Version Detection
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.806812");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2016-01-05 17:56:58 +0530 (Tue, 05 Jan 2016)");
  script_name("Http File Server Detection (HTTP)");

  script_tag(name:"summary", value:"Detection of installed version
  of Http file server.

  This script sends an HTTP GET request and tries to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("HFS/banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port(default:80);

banner = http_get_remote_headers(port: port);
if(!banner)
  exit(0);

if(!concl = egrep(string:banner, pattern:"Server: HFS", icase:TRUE))
  exit(0);

concl = chomp(concl);

version = "unknown";

vers = eregmatch(pattern:"Server: HFS (([0-9.])+([a-z]+)?)", string:banner, icase:TRUE);
if(!isnull(vers[1])) {
  version = vers[1];
  concl = vers[0];
}

set_kb_item(name:"hfs/Installed", value:TRUE);

cpe = build_cpe(value:vers[1], exp:"^([0-9.a-z]+)", base:"cpe:/a:httpfilesever:hfs:");
if(!cpe)
  cpe = "cpe:/a:httpfilesever:hfs";

register_product(cpe:cpe, location:"/", port:port, service:"www");

log_message(data: build_detection_report(app: "Http File Server",
                                         version: version,
                                         install: "/",
                                         cpe: cpe,
                                         concluded: concl),
                                         port: port);
exit(0);

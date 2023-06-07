# Copyright (C) 2016 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807686");
  script_version("2021-10-18T13:34:19+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-10-18 13:34:19 +0000 (Mon, 18 Oct 2021)");
  script_tag(name:"creation_date", value:"2016-05-03 17:32:47 +0530 (Tue, 03 May 2016)");
  script_name("OpenWGA Content Manager Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of OpenWGA Content Manager.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port(default:8080);

url = "/plugin-management/html/homepage:main.int.html";
res = http_get_cache(item:url, port:port);

if(res && res =~ "OpenWG.*Server" && "4f70656e574741e284a220536572766572" >< hexstr(res) && ">Web Content & Application Development Platform<" >< res) {

  install = "/";
  version = "unknown";

  vers = eregmatch(pattern:"OpenWG.*Server ([0-9.]+) Maintenance Release .*Build ([0-9.]+)", string:res);
  if(vers[1] && vers[2])
    version = vers[1] + "." + vers[2];

  set_kb_item(name:"openwga/content_manager/detected", value:TRUE);
  set_kb_item(name:"openwga/content_manager/http/detected", value:TRUE);

  cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:openwga:openwga_content_manager:");
  if(!cpe)
    cpe = "cpe:/a:openwga:openwga_content_manager";

  register_product(cpe:cpe, location:install, port:port, service:"www");

  log_message(data:build_detection_report(app:"OpenWGA Content Manager",
                                          version:version,
                                          install:install,
                                          cpe:cpe,
                                          concluded:vers[0]),
              port:port);
}

exit(99);
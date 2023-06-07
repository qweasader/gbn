# Copyright (C) 2017 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106837");
  script_version("2023-03-09T10:20:45+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:20:45 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"creation_date", value:"2017-05-30 09:34:27 +0700 (Tue, 30 May 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("VICIdial Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of VICIdial.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.vicidial.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

res = http_get_cache(port: port, item: "/vicidial/welcome.php");

if ("Agent Login" >< res && "vicidial/admin.php" >< res && "Timeclock" >< res) {
  version = "unknown";
  build = "unknown";

  url = "/agc/vicidial.php";
  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req);

  vers = eregmatch(pattern: "VERSION: ([0-9a-z.-]+) &nbsp; &nbsp; &nbsp; BUILD: ([0-9-]+)", string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
  }
  if (!isnull(vers[2])) {
    build = vers[2];
    set_kb_item(name: "vicidial/build", value: build);
  }

  set_kb_item(name: "vicidial/detected", value: TRUE);
  set_kb_item(name: "vicidial/http/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9a-z.-]+)", base: "cpe:/a:vicidial:vicidial:");
  if (!cpe)
    cpe = "cpe:/a:vicidial:vicidial";

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "VICIdial", version: version,
                                           install: "/", cpe: cpe, concluded: vers[0], concludedUrl: concUrl,
                                           extra: "Build: " + build),
              port: port);
  exit(0);
}

exit(0);

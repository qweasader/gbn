# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.145300");
  script_version("2021-02-24T08:59:37+0000");
  script_tag(name:"last_modification", value:"2021-02-24 08:59:37 +0000 (Wed, 24 Feb 2021)");
  script_tag(name:"creation_date", value:"2021-02-03 09:25:27 +0000 (Wed, 03 Feb 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("webERP Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of webERP.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.weberp.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/", "/weberp", "/webERP", http_cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  res = http_get_cache(port: port, item: dir + "/index.php");

  if ("<title>webERP Login" >< res && 'name="CompanyNameField"' >< res) {
    version = "unknown";

    url = dir + "/doc/CHANGELOG.md";
    res = http_get_cache(port: port, item: url);

    # ## [v4.15.1] - 2019-06-16
    vers = eregmatch(pattern: "## \[v([0-9a-z.]+)\]", string: res, icase: TRUE);

    if (!isnull(vers[1])) {
      version = vers[1];
      concluded = vers[0];
      concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
    }

    if (version == "unknown") {
      url = dir + "/doc/Change.log";
      res = http_get_cache(port: port, item: url);

      # 8/2/14 Release 4.11.3
      # 1/9/13 Version 4.11.0
      # Version 3.11
      # Version 2.9b
      # 19/11/11 Release 4.06RC3 - 4.06.1
      vers = eregmatch(pattern: "(Release|Version) ([0-9a-z.]+)", string: res, icase: TRUE);

      if (!isnull(vers[2])) {
        version = vers[2];
        concluded = vers[0];
        concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
      }
    }

    if (version == "unknown") {
      url = dir + "/sql/mysql/country_sql/demo.sql";
      req = http_get(port: port, item: url);
      res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

      # INSERT INTO `config` VALUES ('VersionNumber','4.14.1');
      vers = eregmatch(pattern: "'VersionNumber','([0-9a-z.]+)'", string: res, icase: TRUE);

      if (!isnull(vers[1])) {
        version = vers[1];
        concluded = vers[0];
        concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
      }
    }

    set_kb_item(name: "weberp/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9a-z.]+)", base: "cpe:/a:weberp:weberp:");
    if (!cpe)
      cpe = "cpe:/a:weberp:weberp";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "webERP", version: version, install: install, cpe: cpe,
                                             concluded: concluded, concludedUrl: concUrl),
                port: port);
    exit(0);
  }
}

exit(0);

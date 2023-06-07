# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:apache:http_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144374");
  script_version("2021-07-22T02:00:50+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:00:50 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"creation_date", value:"2020-08-10 04:49:18 +0000 (Mon, 10 Aug 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-06 11:15:00 +0000 (Sun, 06 Jun 2021)");

  script_cve_id("CVE-2020-11984");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache HTTP Server 2.4.32 < 2.4.44 mod_proxy_uwsgi Buffer Overflow Vulnerability (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_http_server_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/http_server/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Apache HTTP Server is prone to a buffer overflow vulnerability in mod_proxy_uwsgi.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"mod_proxy_uwsgi is prone to an information disclosure and possible remote code
  execution vulnerability.");

  script_tag(name:"affected", value:"Apache HTTP Server version 2.4.32 to 2.4.43.");

  script_tag(name:"solution", value:"Update to version 2.4.44 or later.");

  script_xref(name:"URL", value:"https://httpd.apache.org/security/vulnerabilities_24.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE, version_regex: "^[0-9]+\.[0-9]+\.[0-9]+"))
  exit(0);

version = infos["version"];
location = infos["location"];

affected = make_list("2.4.39",
                     "2.4.38",
                     "2.4.37",
                     "2.4.35",
                     "2.4.34",
                     "2.4.33");

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.4.44", install_path: location);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);

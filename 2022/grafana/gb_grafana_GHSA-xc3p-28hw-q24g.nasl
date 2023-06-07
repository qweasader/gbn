# Copyright (C) 2022 Greenbone Networks GmbH
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

CPE = "cpe:/a:grafana:grafana";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147615");
  script_version("2022-02-16T03:03:58+0000");
  script_tag(name:"last_modification", value:"2022-02-16 03:03:58 +0000 (Wed, 16 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-10 02:54:40 +0000 (Thu, 10 Feb 2022)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-11 17:27:00 +0000 (Fri, 11 Feb 2022)");

  script_cve_id("CVE-2022-21702");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Grafana XSS Vulnerability (GHSA-xc3p-28hw-q24g)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_grafana_http_detect.nasl");
  script_mandatory_keys("grafana/detected");

  script_tag(name:"summary", value:"Grafana is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker could serve HTML content through the Grafana
  datasource or plugin proxy and trick a user to visit this HTML page using a specially crafted
  link and execute an XSS attack. The attacker could either compromise an existing datasource for a
  specific Grafana instance or either set up its own public service and instruct anyone to set it
  up in their Grafana instance.");

  script_tag(name:"affected", value:"Grafana version 2.0.0-beta1 through 8.3.4.");

  script_tag(name:"solution", value:"Update to version 7.5.15, 8.3.5 or later.");

  script_xref(name:"URL", value:"https://github.com/grafana/grafana/security/advisories/GHSA-xc3p-28hw-q24g");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "2.0.0", test_version_up: "7.5.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.5.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.0", test_version_up: "8.3.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.3.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

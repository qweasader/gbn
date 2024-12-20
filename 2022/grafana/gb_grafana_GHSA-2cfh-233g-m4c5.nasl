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
  script_oid("1.3.6.1.4.1.25623.1.0.148673");
  script_version("2023-10-18T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-10-18 05:05:17 +0000 (Wed, 18 Oct 2023)");
  script_tag(name:"creation_date", value:"2022-09-05 04:01:09 +0000 (Mon, 05 Sep 2022)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-09 03:22:00 +0000 (Fri, 09 Sep 2022)");

  script_cve_id("CVE-2022-31176");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Grafana Image Renderer Vulnerability (GHSA-2cfh-233g-m4c5)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_grafana_http_detect.nasl");
  script_mandatory_keys("grafana/detected");

  script_tag(name:"summary", value:"Grafana is prone to a vulnerability in Grafana Image Renderer.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Chromium browser embedded in the Grafana image renderer
  allows for 'printing' of unauthorized files in a PNG file. This makes it possible for a malicious
  user to retrieve unauthorized files under some network conditions or via a fake datasource (if
  the user has admin permissions in Grafana). This vulnerability permits unauthorized file
  disclosure and is a potential DoS vector through targeting of extremely large files.");

  script_tag(name:"affected", value:"Grafana version 9.x and prior.");

  script_tag(name:"solution", value:"Update to version 8.3.11, 8.4.11, 8.5.11, 9.0.8, 9.1.2 or
  later.");

  script_xref(name:"URL", value:"https://github.com/grafana/grafana-image-renderer/security/advisories/GHSA-2cfh-233g-m4c5");

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

if (version_is_less(version: version, test_version: "8.3.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.3.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.4", test_version_up: "8.4.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.4.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.5", test_version_up: "8.5.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.0", test_version_up: "9.0.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.1", test_version_up: "9.1.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.1.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

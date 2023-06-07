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

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146690");
  script_version("2023-03-01T10:20:05+0000");
  script_tag(name:"last_modification", value:"2023-03-01 10:20:05 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"creation_date", value:"2021-09-09 12:52:00 +0000 (Thu, 09 Sep 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-24 13:43:00 +0000 (Fri, 24 Sep 2021)");

  script_cve_id("CVE-2021-39200", "CVE-2021-39201");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Multiple Vulnerabilities (Sep 2021) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("wordpress/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"WordPress is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-39200: Data exposure vulnerability within the REST API

  - CVE-2021-39201: XSS vulnerability in the block editor

  - The Lodash library has been updated to version 4.17.21 in each branch to incorporate upstream
  security fixes");

  script_tag(name:"affected", value:"WordPress versions 5.4 through 5.8.");

  script_tag(name:"solution", value:"Update to version 5.4.7, 5.5.6, 5.6.5, 5.7.3, 5.8.1 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/news/2021/09/wordpress-5-8-1-security-and-maintenance-release/");

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

if (version_in_range(version: version, test_version: "5.4", test_version2: "5.4.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.5", test_version2: "5.5.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.6", test_version2: "5.6.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.7", test_version2: "5.7.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.7.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version =~ "^5\.8" && version_is_less(version: version, test_version: "5.8.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.8.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

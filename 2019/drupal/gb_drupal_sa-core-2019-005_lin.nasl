# Copyright (C) 2019 Greenbone Networks GmbH
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

CPE = 'cpe:/a:drupal:drupal';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142298");
  script_version("2021-12-01T11:10:56+0000");
  script_tag(name:"last_modification", value:"2021-12-01 11:10:56 +0000 (Wed, 01 Dec 2021)");
  script_tag(name:"creation_date", value:"2019-04-24 09:03:57 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-29 16:23:00 +0000 (Wed, 29 Sep 2021)");

  script_cve_id("CVE-2019-10909", "CVE-2019-10910", "CVE-2019-10911");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Drupal 8.x Multiple Vulnerabilities (SA-CORE-2019-005) (Linux)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_drupal_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Drupal is prone to multiple vulnerabilities in third-party dependencies.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Drupal is prone to multiple vulnerabilities in third-party dependencies:

  - Validation messages were not escaped when using the form theme of the PHP templating engine which, when
    validation messages may contain user input, could result in an XSS. (CVE-2019-10909)

  - Service IDs derived from unfiltered user input could result in the execution of any arbitrary code, resulting
    in possible remote code execution. (CVE-2019-10910)

  - This fixes situations where part of an expiry time in a cookie could be considered part of the username, or
    part of the username could be considered part of the expiry time. An attacker could modify the remember me
    cookie and authenticate as a different user. (CVE-2019-10911)");

  script_tag(name:"affected", value:"Drupal 8.5.x or earlier and 8.6.x.");

  script_tag(name:"solution", value:"Update to version 8.5.15, 8.6.15 or later.");

  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2019-005");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE, version_regex: "^[0-9]\.[0-9]+"))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "8.0", test_version2: "8.5.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.6", test_version2: "8.6.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.6.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
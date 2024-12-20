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

CPE = "cpe:/a:moodle:moodle";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124140");
  script_version("2023-10-19T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-10-19 05:05:21 +0000 (Thu, 19 Oct 2023)");
  script_tag(name:"creation_date", value:"2022-08-17 11:31:42 +0000 (Wed, 17 Aug 2022)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-17 15:41:00 +0000 (Wed, 17 Aug 2022)");

  script_cve_id("CVE-2020-1755", "CVE-2020-1756");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moodle 3.5 <= 3.5.10, 3.6 <= 3.6.8, 3.7 <= 3.7.4, 3.8 <= 3.8.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - MSA-20-0003 / CVE-2020-1755: X-Forwarded-For headers could be used to spoof a user's IP, in
  order to bypass remote address checks.

  - MSA-20-0004 / CVE-2020-1756: Insufficient input escaping in the PHP unit
  webrunner admin tool.");

  script_tag(name:"affected", value:"Moodle versions 3.5 through 3.5.10, 3.6 through 3.6.8, 3.7
  through 3.7.4 and 3.8 through 3.8.1");

  script_tag(name:"solution", value:"Update to version 3.5.11, 3.6.9, 3.7.5, 3.8.2 or later.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=398351");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=398352");

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

if (version_in_range(version: version, test_version: "3.5", test_version2: "3.5.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.5.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.6", test_version2: "3.6.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.6.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.7", test_version2: "3.7.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.7.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.8", test_version2: "3.8.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.8.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

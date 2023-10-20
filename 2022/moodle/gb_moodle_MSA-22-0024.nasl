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
  script_oid("1.3.6.1.4.1.25623.1.0.126164");
  script_version("2023-10-19T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-10-19 05:05:21 +0000 (Thu, 19 Oct 2023)");
  script_tag(name:"creation_date", value:"2022-10-10 10:40:17 +0000 (Mon, 10 Oct 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-04 16:49:00 +0000 (Tue, 04 Oct 2022)");

  script_cve_id("CVE-2022-40314");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moodle 3.9 < 3.9.17, 3.11 < 3.11.10, 4.0 < 4.0.4 RCE Vulnerability (MSA-22-0024)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A remote code execution risk when restoring backup files
  originating from Moodle 1.9 was identified.");

  script_tag(name:"affected", value:"Moodle versions 3.9 through 3.9.16, 3.11 through 3.11.9 and 4.0
  through 4.0.3.");

  script_tag(name:"solution", value:"Update to version 3.9.17, 3.11.10, 4.0.4 or later.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=438393");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_in_range(version: version, test_version: "3.9", test_version2: "3.9.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.17", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if(version_in_range(version: version, test_version: "3.11", test_version2: "3.11.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.11.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if(version_in_range(version: version, test_version: "4.0", test_version2: "4.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

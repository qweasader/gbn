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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112845");
  script_version("2021-07-05T11:01:33+0000");
  script_tag(name:"last_modification", value:"2021-07-05 11:01:33 +0000 (Mon, 05 Jul 2021)");
  script_tag(name:"creation_date", value:"2020-11-27 12:46:11 +0000 (Fri, 27 Nov 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-02 19:53:00 +0000 (Wed, 02 Dec 2020)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-25698", "CVE-2020-25699", "CVE-2020-25700", "CVE-2020-25701");

  script_name("Moodle < 3.5.14, 3.7.x < 3.7.9, 3.8.x < 3.8.6, 3.9.x < 3.9.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Users' enrolment capabilities are not being sufficiently checked when they are restored into an existing
  course, which could lead to them unenrolling users without having permission to do so

  - Insufficient capability checks could lead to users with the ability to course restore adding
  additional capabilities to roles within that course

  - Some database module web services allow students to add entries within groups they do not belong to

  - If the upload course tool is used to delete an enrollment method which does not exist or is not already
  enabled, the tool will erroneously enable that enrollment method. This could lead to unintended users gaining access to the course.");

  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacker to
  modify system files or information or gain unauthorized access to courses.");

  script_tag(name:"affected", value:"Moodle through version 3.5.13, versions 3.7.0 through 3.7.8,
  3.8.0 through 3.8.5 and 3.9.0 through 3.9.2.");

  script_tag(name:"solution", value:"Update to version 3.5.14, 3.7.9, 3.8.6, 3.9.3 or 3.10 respectively.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=413935");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=413936");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=413938");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=413939");

  exit(0);
}

CPE = "cpe:/a:moodle:moodle";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "3.5.14" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.5.14", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.7.0", test_version2: "3.7,8" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.7.9", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.8.0", test_version2: "3.8.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.8.6", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.9.0", test_version2: "3.9.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.9.3", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

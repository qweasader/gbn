# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.113362");
  script_version("2021-08-27T12:01:24+0000");
  script_tag(name:"last_modification", value:"2021-08-27 12:01:24 +0000 (Fri, 27 Aug 2021)");
  script_tag(name:"creation_date", value:"2019-04-02 12:35:05 +0000 (Tue, 02 Apr 2019)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-16 18:48:00 +0000 (Fri, 16 Oct 2020)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-3848", "CVE-2019-3849");

  script_name("Moodle CMS 3.4.x <= 3.4.7, 3.5.x <= 3.5.4 and 3.6.x <= 3.6.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle CMS is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Permissions are not correctly checked before loading event information
    into the calendar's edit event model popup, so logged in non guest-users
    can view unauthorised calendar events

  - Users can assign themselves an escalated role within courses or content
    accessed via LTI by modifying the request to the LTI publisher site");
  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacker to access
  and modify sensitive information.");
  script_tag(name:"affected", value:"Moodle CMS versions 3.4.0 through 3.4.7, 3.5.0 through 3.5.4 and 3.6.0 through 3.6.2.");
  script_tag(name:"solution", value:"Update to version 3.4.8, 3.5.5 or 3.6.3 respectively.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=384011#p1547743");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=384011#p1547744");

  exit(0);
}

CPE = "cpe:/a:moodle:moodle";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_in_range( version: version, test_version: "3.4.0", test_version2: "3.4.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.4.8" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.5.0", test_version2: "3.5.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.5.5" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.6.0", test_version2: "3.6.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.6.3" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

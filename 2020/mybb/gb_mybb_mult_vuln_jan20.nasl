# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.113620");
  script_version("2021-08-11T08:56:08+0000");
  script_tag(name:"last_modification", value:"2021-08-11 08:56:08 +0000 (Wed, 11 Aug 2021)");
  script_tag(name:"creation_date", value:"2020-01-06 12:12:21 +0000 (Mon, 06 Jan 2020)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-08 19:57:00 +0000 (Wed, 08 Jan 2020)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-20225");

  script_name("MyBB < 1.8.22 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_mybb_detect.nasl");
  script_mandatory_keys("MyBB/installed");

  script_tag(name:"summary", value:"MyBB is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Installer RCE on settings file write

  - Arbitrary upload paths & Local File Inclusion RCE

  - XSS via insufficient HTML sanitization of Blog feed & Extend data

  - Open redirect on login

  - SCEditor reflected XSS");

  script_tag(name:"impact", value:"Successful exploitation would result in an attacker being
  able to inject arbitrary code into the site or even execute arbitrary code on the target machine.");

  script_tag(name:"affected", value:"MyBB through version 1.8.21.");

  script_tag(name:"solution", value:"Update to version 1.8.22.");

  script_xref(name:"URL", value:"https://blog.mybb.com/2019/12/30/mybb-1-8-22-released-security-maintenance-release/");

  exit(0);
}

CPE = "cpe:/a:mybb:mybb";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "1.8.22" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.8.22", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

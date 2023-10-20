# Copyright (C) 2023 Greenbone Networks GmbH
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

CPE = "cpe:/a:djangoproject:django";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127319");
  script_version("2023-10-12T05:05:32+0000");
  script_tag(name:"last_modification", value:"2023-10-12 05:05:32 +0000 (Thu, 12 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-02-02 07:50:07 +0000 (Thu, 02 Feb 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-08 19:53:00 +0000 (Wed, 08 Feb 2023)");

  script_cve_id("CVE-2023-23969");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Django 3.2.x < 3.2.17, 4.0.x < 4.0.9, 4.1.x < 4.1.6 DoS Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_django_detect_win.nasl");
  script_mandatory_keys("django/windows/detected");

  script_tag(name:"summary", value:"Django is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The parsed values of Accept-Language headers are cached in
  order to avoid repetitive parsing. This leads to a potential denial-of-service vector via
  excessive memory usage if large header values are sent.");

  script_tag(name:"affected", value:"Django versions 3.2.x prior to 3.2.17, 4.0.x prior to 4.0.9,
  4.1.x prior to 4.1.6.");

  script_tag(name:"solution", value:"Update to version 3.2.17, 4.0.9, 4.1.6 or later.");

  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2023/feb/01/security-releases/");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) )
  exit( 0 );

version = infos[ "version" ];
location = infos[ "location" ];

if( version_in_range_exclusive( version: version, test_version_lo: "3.2.0", test_version_up: "3.2.17" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.2.17", install_path: location );
  security_message( port: 0, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "4.0.0", test_version_up: "4.0.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.0.9", install_path: location );
  security_message( port: 0, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "4.1.0", test_version_up: "4.1.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.1.6", install_path: location );
  security_message( port: 0, data: report );
  exit( 0 );
}

exit( 99 );

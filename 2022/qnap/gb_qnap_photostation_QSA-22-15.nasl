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

CPE = "cpe:/a:qnap:photo_station";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170098");
  script_version("2022-05-25T12:20:12+0000");
  script_tag(name:"last_modification", value:"2022-05-25 12:20:12 +0000 (Wed, 25 May 2022)");
  script_tag(name:"creation_date", value:"2022-05-09 09:08:13 +0000 (Mon, 09 May 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-13 20:10:00 +0000 (Fri, 13 May 2022)");

  script_cve_id("CVE-2021-44057");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP Photo Station Improper Authentication Vulnerability (QSA-22-15)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_photo_station_detect.nasl");
  script_mandatory_keys("qnap/nas/PhotoStation/detected");

  script_tag(name:"summary", value:"QNAP Photo Station is prone to an improper authentication
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"If exploited, this vulnerability allows attackers to compromise the
  security of the system.");

  script_tag(name:"affected", value:"QNAP Photo Station versions prior to 5.4.13, 5.5.x through
  5.7.15, 5.8.x through 6.0.19.");

  script_tag(name:"solution", value:"Update to version 5.4.13, 5.7.16, 6.0.20 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-22-15");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if ( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if ( version_is_less( version:version, test_version:"5.4.13" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"5.4.13", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if ( version_in_range( version:version, test_version:"5.5.0", test_version2:"5.7.15" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"5.7.16", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if ( version_in_range( version:version, test_version:"5.8.0", test_version2:"6.0.19" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"6.0.20", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

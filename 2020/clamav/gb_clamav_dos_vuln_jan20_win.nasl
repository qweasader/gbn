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
  script_oid("1.3.6.1.4.1.25623.1.0.113624");
  script_version("2022-03-01T12:03:40+0000");
  script_tag(name:"last_modification", value:"2022-03-01 12:03:40 +0000 (Tue, 01 Mar 2022)");
  script_tag(name:"creation_date", value:"2020-01-20 11:14:38 +0000 (Mon, 20 Jan 2020)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-19 23:15:00 +0000 (Thu, 19 Mar 2020)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-15961");

  script_name("ClamAV <= 0.101.4, 0.102.0 DoS Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_clamav_smb_login_detect.nasl", "gb_clamav_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("clamav/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"ClamAV is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to inefficient MIME parsing routines that result in
  extremely long scan times of specially formatted email files. An attacker could
  exploit this vulnerability by sending a crafted email file to an affected device.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to cause the ClamAV scanning
  process to scan the crafted email file indefinitely, resulting in a denial of service.");

  script_tag(name:"affected", value:"ClamAV through version 0.101.4 and version 0.102.0.");

  script_tag(name:"solution", value:"Update to version 0.101.5 or 0.102.1 respectively.");

  script_xref(name:"URL", value:"https://bugzilla.clamav.net/show_bug.cgi?id=12380");
  script_xref(name:"URL", value:"https://quickview.cloudapps.cisco.com/quickview/bug/CSCvr56010");

  exit(0);
}

CPE = "cpe:/a:clamav:clamav";

include( "host_details.inc" );
include( "version_func.inc" );

if( isnull( port = get_app_port( cpe: CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "0.101.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "0.101.5", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_is_equal( version: version, test_version: "0.102.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "0.102.1", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

# Copyright (C) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:isc:bind";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807203");
  script_version("2023-03-07T10:19:54+0000");
  script_tag(name:"last_modification", value:"2023-03-07 10:19:54 +0000 (Tue, 07 Mar 2023)");
  script_tag(name:"creation_date", value:"2016-01-28 12:39:11 +0530 (Thu, 28 Jan 2016)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2012-5166");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ISC BIND DNS RDATA Handling Remote DoS Vulnerability (Jan 2016)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_isc_bind_consolidation.nasl");
  script_mandatory_keys("isc/bind/detected");

  script_tag(name:"summary", value:"ISC BIND is prone to a remote denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the DNS RDATA Handling in ISC
  BIND.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause a DoS.");

  script_tag(name:"affected", value:"ISC BIND versions 9.2.x through 9.6.x, 9.4-ESV through
  9.4-ESV-R5-P1, 9.6-ESV through 9.6-ESV-R7-P3, 9.7.0 through 9.7.6-P3, 9.8.0 through 9.8.3-P3 and
  9.9.0 through 9.9.1-P3.");

  script_tag(name:"solution", value:"Update to version 9.7.7, 9.7.6-P4, 9.6-ESV-R8, 9.6-ESV-R7-P4,
  9.8.4, 9.8.3-P4, 9.9.2, 9.9.1-P4 or later.");

  script_xref(name:"URL", value:"https://kb.isc.org/docs/aa-00801");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55852");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_full( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
proto = infos["proto"];
location = infos["location"];

if( version_in_range( version:version, test_version:"9.2", test_version2:"9.6" ) ) {
  fix = "9.7.7";
  VULN = TRUE;
}

else if( version_in_range( version:version, test_version:"9.4", test_version2:"9.4r5_p1" ) ) {
  fix = "9.6-ESV-R8";
  VULN = TRUE;
}

else if( version_in_range( version:version, test_version:"9.7.0", test_version2:"9.7.6p3" ) ) {
  fix = "9.7.6-P4";
  VULN = TRUE;
}

else if( version_in_range( version:version, test_version:"9.8.0", test_version2:"9.8.3p3" ) ) {
  fix = "9.8.3-P4";
  VULN = TRUE;
}

else if( version_in_range( version:version, test_version:"9.6", test_version2:"9.6r7_p3" ) ) {
  fix = "9.6-ESV-R7-P4";
  VULN = TRUE;
}

else if( version_in_range( version:version, test_version:"9.9.0", test_version2:"9.9.1p3" ) ) {
  fix = "9.9.1-P4";
  VULN = TRUE;
}

if( VULN ) {
  report = report_fixed_ver( installed_version:version, fixed_version:fix, install_path:location );
  security_message( data:report, port:port, proto:proto );
  exit( 0 );
}

exit( 99 );

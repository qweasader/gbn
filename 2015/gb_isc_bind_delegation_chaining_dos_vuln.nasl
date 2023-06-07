###############################################################################
# OpenVAS Vulnerability Test
#
# ISC BIND Delegation Handling Denial of Service Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:isc:bind";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806080");
  script_version("2021-03-26T13:22:13+0000");
  script_cve_id("CVE-2014-8500");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2021-03-26 13:22:13 +0000 (Fri, 26 Mar 2021)");
  script_tag(name:"creation_date", value:"2015-10-07 15:17:54 +0530 (Wed, 07 Oct 2015)");
  script_name("ISC BIND Delegation Handling Denial of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_isc_bind_consolidation.nasl");
  script_mandatory_keys("isc/bind/detected");

  script_xref(name:"URL", value:"https://kb.isc.org/docs/aa-01216");

  script_tag(name:"summary", value:"ISC BIND is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists because ISC BIND does not handle
  delegation chaining properly.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to cause a denial of service for clients.");

  script_tag(name:"affected", value:"ISC BIND versions 9.0.x through 9.8.x,
  9.9.0 through 9.9.6, and 9.10.0 through 9.10.1.");

  script_tag(name:"solution", value:"Update to ISC BIND version 9.9.6-p1 or
  9.10.1-p1 or later for branches of BIND (9.9 and 9.10).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

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

if( version_in_range( version:version, test_version:"9.0", test_version2:"9.8.6" ) ) {
  fix = "9.9.6-P1";
  VULN = TRUE;
}

if( version_in_range( version:version, test_version:"9.9.0", test_version2:"9.9.6" ) ) {
  fix = "9.9.6-P1";
  VULN = TRUE;
}

if( version_in_range( version:version, test_version:"9.10.0", test_version2:"9.10.1" ) ) {
  fix = "9.10.1-P1";
  VULN = TRUE;
}

if( VULN ) {
  report = report_fixed_ver( installed_version:version, fixed_version:fix, install_path:location );
  security_message( data:report, port:port, proto:proto );
  exit( 0 );
}

exit( 99 );

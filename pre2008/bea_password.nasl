# OpenVAS Vulnerability Test
# Description: BEA WebLogic Operator/Admin Password Disclosure Vulnerability
#
# Authors:
# Astharot <astharot@zone-h.org>
#
# Copyright:
# Copyright (C) 2004 Astharot
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12043");
  script_version("2022-05-12T09:32:01+0000");
  script_tag(name:"last_modification", value:"2022-05-12 09:32:01 +0000 (Thu, 12 May 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-1757");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_name("BEA WebLogic Operator/Admin Password Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 Astharot");
  script_family("Web Servers");
  script_dependencies("gb_oracle_weblogic_consolidation.nasl");
  script_mandatory_keys("oracle/weblogic/detected");

  script_xref(name:"URL", value:"http://dev2dev.bea.com/resourcelibrary/advisoriesnotifications/BEA04_51.00.jsp");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9501");
  script_xref(name:"URL", value:"https://exchange.xforce.ibmcloud.com/vulnerabilities/14957");

  script_tag(name:"solution", value:"The vendor has release updates. Please see the references for
  more information.");

  script_tag(name:"summary", value:"BEA WebLogic Server and WebLogic Express are prone to a
  vulnerability that may result in the disclosure of Operator or Admin passwords.");

  script_tag(name:"impact", value:"An attacker who has interactive access to the affected managed
  server, may potentially exploit this issue in a timed attack to harvest credentials when the
  managed server fails during the boot process.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

CPE = "cpe:/a:bea:weblogic_server";

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe: CPE, nofork: TRUE ) )
  exit( 0 );

if( version_is_less( version: version, test_version: "6.1sp6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.1 SP6" );
  security_message( data: report, port: 0 );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "7.0.0.0", test_version2: "7.0sp4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.0 SP4" );
  security_message( data: report, port: 0 );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "8.0.0.0", test_version2: "8.1sp2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.1 SP2" );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );

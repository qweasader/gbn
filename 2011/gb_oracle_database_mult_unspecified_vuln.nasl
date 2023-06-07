###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle Database Server Multiple Unspecified Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH
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

CPE = "cpe:/a:oracle:database_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802527");
  script_version("2022-04-28T13:38:57+0000");
  script_cve_id("CVE-2006-0256", "CVE-2006-0257", "CVE-2006-0258", "CVE-2006-0259",
                "CVE-2006-0260", "CVE-2006-0261", "CVE-2006-0262", "CVE-2006-0263",
                "CVE-2006-0265", "CVE-2006-0266", "CVE-2006-0267", "CVE-2006-0268",
                "CVE-2006-0269", "CVE-2006-0270", "CVE-2006-0271", "CVE-2006-0272",
                "CVE-2006-0551", "CVE-2006-0547", "CVE-2006-0548", "CVE-2006-0549",
                "CVE-2006-0552", "CVE-2006-0586");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-12-07 12:34:24 +0530 (Wed, 07 Dec 2011)");
  script_name("Oracle Database Server Multiple Unspecified Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("oracle_tnslsnr_version.nasl");
  script_mandatory_keys("OracleDatabaseServer/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/18493");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/16287");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/16294");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/16384");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/545804");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/871756");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/150332");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/983340");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1015499");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/whatsnew/index.html");
  script_xref(name:"URL", value:"http://lists.grok.org.uk/pipermail/full-disclosure/2006-January/041464.html");

  script_tag(name:"impact", value:"An unspecified impact and attack vectors.");
  script_tag(name:"affected", value:"Oracle Database server versions 8.1.7.4, 9.0.1.5, 9.2.0.6, 10.1.0.3, 9.2.0.7,
  10.1.0.5, 10.2.0.1, 9.0.1.5 FIPS and 10.1.0.4");
  script_tag(name:"insight", value:"The flaws are due to unspecified errors in the multiple components.");
  script_tag(name:"summary", value:"Oracle database is prone to multiple unspecified vulnerabilities.");
  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujan2006-082403.html");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_equal( version:vers, test_version:"10.2.0.0") ||
    version_in_range( version:vers, test_version:"9.0.1", test_version2:"9.0.1.4" ) ||
    version_in_range( version:vers, test_version:"8.1.0", test_version2:"8.1.7.3" ) ||
    version_in_range( version:vers, test_version:"9.2.0", test_version2:"9.2.0.6" ) ||
    version_in_range( version:vers, test_version:"10.1.0", test_version2:"10.1.0.4" ) ||
    version_is_equal( version:vers, test_version:"8.1.7.4" ) ||
    version_is_equal( version:vers, test_version:"9.0.1.5" ) ||
    version_is_equal( version:vers, test_version:"9.2.0.7" ) ||
    version_is_equal( version:vers, test_version:"10.1.0.5" ) ||
    version_is_equal( version:vers, test_version:"10.2.0.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
###############################################################################
# OpenVAS Vulnerability Test
#
# Squid Multiple Remote Denial of Service Vulnerabilities
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:squid-cache:squid";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100249");
  script_version("2022-07-20T10:33:02+0000");
  script_tag(name:"last_modification", value:"2022-07-20 10:33:02 +0000 (Wed, 20 Jul 2022)");
  script_tag(name:"creation_date", value:"2009-07-27 22:49:07 +0200 (Mon, 27 Jul 2009)");
  script_cve_id("CVE-2009-2621");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Squid Multiple Remote DoS Vulnerabilities (SQUID-2009:2)");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("gb_squid_http_detect.nasl");
  script_mandatory_keys("squid/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35812");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2009_2.txt");

  script_tag(name:"summary", value:"Squid is prone to multiple remote denial of service (DoS) vulnerabilities.");

  script_tag(name:"impact", value:"Successfully exploiting these issues allow remote attackers to crash
  the affected application, denying further service to legitimate users.");

  script_tag(name:"affected", value:"Squid versions 3.0.STABLE16, 3.1.0.11 and prior.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_in_range( version:vers, test_version:"3.1.0", test_version2:"3.1.0.11" ) ||
    version_in_range( version:vers, test_version:"3.1", test_version2:"3.1.5" ) ||
    version_in_range( version:vers, test_version:"3.0", test_version2:"3.0.STABLE16" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.0.STABLE17/3.1.0.12/3.1.6" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
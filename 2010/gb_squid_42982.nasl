###############################################################################
# OpenVAS Vulnerability Test
#
# Squid String Processing NULL Pointer Dereference Denial Of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100789");
  script_version("2022-07-20T10:33:02+0000");
  script_tag(name:"last_modification", value:"2022-07-20 10:33:02 +0000 (Wed, 20 Jul 2022)");
  script_tag(name:"creation_date", value:"2010-09-07 15:26:31 +0200 (Tue, 07 Sep 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2010-3072");
  script_name("Squid String Processing NULL Pointer Dereference DoS Vulnerability (SQUID-2010:3)");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_squid_http_detect.nasl");
  script_mandatory_keys("squid/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42982");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2010_3.txt");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more
  information.");

  script_tag(name:"summary", value:"Squid is prone to a remote denial of service (DoS)
  vulnerability caused by a NULL pointer dereference.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to cause the application to
  crash, denying service to legitimate users. Due to the nature of the issue, code execution may be
  possible, however, it has not been confirmed.");

  script_tag(name:"affected", value:"Squid versions 3.0 through 3.0.STABLE25, 3.1 through
  3.1.7 and 3.2 through 3.2.0.1.");

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

if( version_in_range( version:vers, test_version:"3.1", test_version2:"3.1.7" ) ||
    version_in_range( version:vers, test_version:"3.2", test_version2:"3.2.0.1" ) ||
    version_in_range( version:vers, test_version:"3.0", test_version2:"3.0.STABLE25" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.0.STABLE26/3.1.8/3.2.0.2" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

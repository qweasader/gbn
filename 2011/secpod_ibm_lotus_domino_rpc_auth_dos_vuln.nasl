# Copyright (C) 2011 Greenbone Networks GmbH
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

CPE = "cpe:/a:ibm:lotus_domino";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.2497");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-12-29 10:48:29 +0530 (Thu, 29 Dec 2011)");

  script_cve_id("CVE-2011-1393");

  script_name("IBM Lotus Domino Notes RPC Authentication Processing Denial of Service Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_hcl_domino_consolidation.nasl");
  script_mandatory_keys("hcl/domino/detected");

  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to cause a denial
  of service via a specially crafted packet.");

  script_tag(name:"affected", value:"IBM Lotus Domino Versions 8.x before 8.5.2 FP4");

  script_tag(name:"insight", value:"The flaw is due to an error when processing certain RPC operations
  related to authentication and can be exploited to crash the Domino server via a specially crafted packet.");

  script_tag(name:"solution", value:"Upgrade to IBM Lotus Domino version 8.5.2 FP4 or 8.5.3 or later.");

  script_tag(name:"summary", value:"IBM Lotus Domino Server is prone to a denial of service (DoS) vulnerability.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47331");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51167");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/71805");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21575247");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( version_in_range( version:version, test_version:"8.0", test_version2:"8.5.2.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version:"8.5.2 FP4" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

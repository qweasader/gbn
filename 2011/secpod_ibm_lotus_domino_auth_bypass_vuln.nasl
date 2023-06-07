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
  script_oid("1.3.6.1.4.1.25623.1.0.902420");
  script_version("2022-02-17T14:14:34+0000");
  script_tag(name:"last_modification", value:"2022-02-17 14:14:34 +0000 (Thu, 17 Feb 2022)");
  script_tag(name:"creation_date", value:"2011-05-09 15:38:03 +0200 (Mon, 09 May 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2011-1519", "CVE-2011-1520");

  script_name("IBM Lotus Domino Cookie File Authentication Bypass Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/43860");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0758");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-110/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/517119/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_hcl_domino_consolidation.nasl");
  script_mandatory_keys("hcl/domino/detected");

  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to bypass the
  authentication mechanism by providing a malicious UNC path to COOKIEFILE.");

  script_tag(name:"affected", value:"IBM Lotus Domino versions 7.x and 8.x");

  script_tag(name:"insight", value:"The flaw is due to an error in the Server Controller authentication
  mechanism, which does not properly verify the COOKIEFILE path before using it to retrieve user's credentials.");

  script_tag(name:"solution", value:"Upgrade to version 8.5.2 FP3 or 8.5.3 or later.");

  script_tag(name:"summary", value:"IBM Lotus Domino Server is prone to an authentication bypass vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( version_is_less( version:version, test_version:"8.5.2.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version:"8.5.2 FP3" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

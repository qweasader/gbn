###############################################################################
# OpenVAS Vulnerability Test
#
# IBM Domino Email Message Cross-Site Scripting Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:ibm:lotus_domino";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803787");
  script_version("2022-04-25T14:50:49+0000");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-12-26 10:59:41 +0530 (Thu, 26 Dec 2013)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2013-4063", "CVE-2013-4064", "CVE-2013-4065");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_name("IBM Domino Email Message Cross-Site Scripting Vulnerabilities");

  script_tag(name:"summary", value:"IBM Lotus Domino is prone to  multiple cross-site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Upgrade to IBM Lotus Domino version 8.5.3 FP6, 9.0.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"insight", value:"Multiple flaws are due to certain unspecified input related to active content
  in e-mail messages, ultra-light mode, is not properly sanitised before being used.");

  script_tag(name:"affected", value:"IBM Domino 8.5.x before 8.5.3 FP6 and 9.0.x before 9.0.1.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary HTML
  and script code in a user's browser session in context of an affected site.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/56164");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64444");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64445");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64451");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/86594");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21659959");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_hcl_domino_consolidation.nasl");
  script_mandatory_keys("hcl/domino/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!version = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version_is_equal(version:version, test_version:"9.0.0") ||
   version_in_range(version:version, test_version:"8.5.0.0", test_version2:"8.5.3.5")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"8.5.3 FP6 / 9.0.1");
  security_message(port:0, data: report);
  exit(0);
}

exit(99);

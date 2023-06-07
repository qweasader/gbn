###############################################################################
# OpenVAS Vulnerability Test
#
# IBM Domino IMAP Server Buffer Overflow Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:ibm:lotus_domino";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810961");
  script_version("2022-04-13T11:57:07+0000");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"creation_date", value:"2017-06-27 14:09:35 +0530 (Tue, 27 Jun 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2007-1675");

  script_name("IBM Domino IMAP Server Buffer Overflow Vulnerability");

  script_tag(name:"summary", value:"IBM Domino is prone to a buffer overflow vulnerability");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a boundary condition
  error in the CRAM-MD5 authentication mechanism in the IMAP server.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  to execute arbitrary code within the context of the affected application.
  Failed exploit attempts will result in a denial of service.");

  script_tag(name:"affected", value:"IBM Domino 6.5.x before 6.5.5 Fix Pack 3 (FP3) and 7.x before 7.0.2 FP1.");

  script_tag(name:"solution", value:"Upgrade to IBM Domino 6.5.5 Fix Pack 3 (FP3)
  or 6.5.6 or 7.0.2 Fix Pack 1 (FP1) or 7.0.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21257028");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/23172");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/3616");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_hcl_domino_consolidation.nasl");
  script_mandatory_keys("hcl/domino/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version =~ "^(6\.5\.)") {
  if(version_is_less(version:version, test_version:"6.5.5.3")) {
    fix = "6.5.5 Fix Pack 3 or 6.5.6";
  }
}
else if(version =~ "^(7\.0)") {
  if(version_is_less(version:version, test_version:"7.0.2.1")) {
    fix = "7.0.2 Fix Pack 1 or 7.0.3";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix);
  security_message(data:report, port:0);
  exit(0);
}

exit(99);

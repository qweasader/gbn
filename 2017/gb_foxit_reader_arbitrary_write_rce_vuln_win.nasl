###############################################################################
# OpenVAS Vulnerability Test
#
# Foxit Reader Arbitrary Write RCE Vulnerability (Windows)
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

CPE = "cpe:/a:foxitsoftware:reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811501");
  script_version("2022-04-13T11:57:07+0000");
  script_cve_id("CVE-2017-10994");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-24 01:29:00 +0000 (Thu, 24 Aug 2017)");
  script_tag(name:"creation_date", value:"2017-07-11 11:24:37 +0530 (Tue, 11 Jul 2017)");
  script_name("Foxit Reader Arbitrary Write RCE Vulnerability (Windows)");

  script_tag(name:"summary", value:"Foxit Reader is prone to an arbitrary write RCE vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an input validation
  error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code within the context of the affected
  application. Failed exploit attempts will likely cause a denial-of-service
  condition.");

  script_tag(name:"affected", value:"Foxit Reader version prior to 8.3.1 on
  windows");

  script_tag(name:"solution", value:"Upgrade to Foxit Reader version 8.3.1 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99499");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_foxit_reader_detect_portable_win.nasl");
  script_mandatory_keys("foxit/reader/ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!foxitVer = get_app_version(cpe:CPE, nofork:TRUE)){
  exit(0);
}

## 8.3.1 == 8.3.1.21155
if(version_is_less(version:foxitVer, test_version:"8.3.1.21155"))
{
  report = report_fixed_ver(installed_version:foxitVer, fixed_version:"8.3.1");
  security_message(data:report);
  exit(0);
}

###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Acrobat DC (Classic Track) Security Updates (apsb19-02)-Windows
#
# Authors:
# Vidita V Koushik <vidita@secpod.com>
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:acrobat_dc_classic";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814809");
  script_version("2021-10-07T07:48:17+0000");
  script_cve_id("CVE-2018-16011", "CVE-2018-16018");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-10-07 07:48:17 +0000 (Thu, 07 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-21 16:20:00 +0000 (Wed, 21 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-01-04 11:43:03 +0530 (Fri, 04 Jan 2019)");
  script_name("Adobe Acrobat DC (Classic Track) Security Updates (apsb19-02) - Windows");

  script_tag(name:"summary", value:"Adobe Acrobat DC Classic 2015 is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Use after free error.

  - Security bypass error.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to conduct arbitrary code execution in the context of the current
  user and escalate privileges.");

  script_tag(name:"affected", value:"Adobe Acrobat DC Classic 2015 version 2015.x
  before 2015.006.30461 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Acrobat DC Classic 2015 version
  2015.006.30464 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb19-02.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_acrobat_dc_classic_detect_win.nasl");
  script_mandatory_keys("Adobe/AcrobatDC/Classic/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

## 2015.006.30461 => 15.006.30461
if(version_in_range(version:vers, test_version:"15.0", test_version2:"15.006.30461")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"15.006.30464 (2015.006.30464)", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);

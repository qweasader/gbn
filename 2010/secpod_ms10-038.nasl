# Copyright (C) 2010 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902068");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-06-09 17:19:57 +0200 (Wed, 09 Jun 2010)");
  script_cve_id("CVE-2010-0821", "CVE-2010-0822", "CVE-2010-0823", "CVE-2010-0824",
                "CVE-2010-1246", "CVE-2010-1245", "CVE-2010-1247", "CVE-2010-1249",
                "CVE-2010-1248", "CVE-2010-1250", "CVE-2010-1251", "CVE-2010-1252",
                "CVE-2010-1253");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Office Excel Remote Code Execution Vulnerabilities (2027452)");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-038");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40518");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40520");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40521");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40522");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40523");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40524");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40525");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40526");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40527");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40528");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40529");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40530");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40531");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl", "secpod_ms_office_detection_900025.nasl");
  script_mandatory_keys("MS/Office/Ver", "MS/Office/Prdts/Installed");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code by
  tricking a user into opening a specially crafted Excel document.");

  script_tag(name:"affected", value:"- Microsoft Office Excel 2002 Service Pack 3

  - Microsoft Office Excel 2003 Service Pack 3

  - Microsoft Office Excel 2007 Service Pack 1/2

  - Microsoft Office Excel Viewer Service Pack 1/2");

  script_tag(name:"insight", value:"These issues are caused by memory corruption and buffer overflow errors when
  parsing certain objects or records in a specially crafted Excel document.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS10-038.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("secpod_reg.inc");
include("version_func.inc");

if(hotfix_check_sp(win2k:5, xp:4, win2003:3) <= 0){
  exit(0);
}

excelVer = get_kb_item("SMB/Office/Excel/Version");
if(excelVer =~ "^1[0-2]\.0")
{
  if(version_in_range(version:excelVer, test_version:"10.0", test_version2:"10.0.6861") ||
     version_in_range(version:excelVer, test_version:"11.0", test_version2:"11.0.8323") ||
     version_in_range(version:excelVer, test_version:"12.0", test_version2:"12.0.6535.5001"))
  {
    report = report_fixed_ver(installed_version:excelVer, vulnerable_range:"10.0 - 10.0.6861, 11.0 - 11.0.8323, 12.0 - 12.0.6535.5001");
    security_message(port:0, data:report);
    exit(0);
  }
}

excelVer = get_kb_item("SMB/Office/XLView/Version");
if(excelVer && excelVer =~ "^12\.0")
{
  # Xlview.exe 12 < 12.0.6535.5000
  if(version_in_range(version:excelVer, test_version:"12.0", test_version2:"12.0.6535.4999")){
    report = report_fixed_ver(installed_version:excelVer, vulnerable_range:"12.0 - 12.0.6535.4999");
    security_message(port:0, data:report);
  }
}

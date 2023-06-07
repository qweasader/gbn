###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Multiple Vulnerabilities (KB4048955)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812088");
  script_version("2022-04-13T11:57:07+0000");
  script_cve_id("CVE-2017-11839", "CVE-2017-11840", "CVE-2017-11841", "CVE-2017-11843",
                "CVE-2017-11873", "CVE-2017-11874", "CVE-2017-11791", "CVE-2017-11803",
                "CVE-2017-11827", "CVE-2017-11833", "CVE-2017-11834", "CVE-2017-11836",
                "CVE-2017-11837", "CVE-2017-11838", "CVE-2017-11844", "CVE-2017-11846",
                "CVE-2017-11848", "CVE-2017-11855", "CVE-2017-11856", "CVE-2017-11858",
                "CVE-2017-11861", "CVE-2017-11862", "CVE-2017-11863", "CVE-2017-11866",
                "CVE-2017-11869", "CVE-2017-11870", "CVE-2017-11871");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-30 19:07:00 +0000 (Thu, 30 Nov 2017)");
  script_tag(name:"creation_date", value:"2017-11-15 08:12:00 +0530 (Wed, 15 Nov 2017)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4048955)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4048955");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error when Internet Explorer improperly accesses objects in memory.

  - An error in the way that Microsoft Edge handles cross-origin requests.

  - An error when the scripting engine does not properly handle objects in memory
    in Internet Explorer.

  - An error in the way the scripting engine handles objects in memory in Microsoft
    browsers.

  - An error in the way that the scripting engine handles objects in memory in
    Microsoft Edge.

  - An error in Microsoft Edge as a result of how memory is accessed in code
    compiled by the Edge Just-In-Time (JIT) compiler that allows Control Flow Guard
    (CFG) to be bypassed.

  - An error in the way that Microsoft browsers access objects in memory.

  - An error when Microsoft Edge improperly handles objects in memory.

  - An error when Internet Explorer improperly handles page content, which could
    allow an attacker to detect the navigation of the user leaving a maliciously
    crafted page.

  - An error when the scripting engine does not properly handle objects in memory
    in Microsoft browsers.

  - An error in Microsoft Edge when the Edge Content Security Policy (CSP) fails to
    properly validate certain specially crafted documents.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to gain the same user rights as the current user, determine the origin of all
  webpages in the affected browser, gain access to potentially sensitive
  information, bypass certain security features and trick a user into loading a
  page containing malicious content.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 1709 for 32-bit Systems

  - Microsoft Windows 10 Version 1709 for 64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4048955");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101735");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101734");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101740");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101728");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101750");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101715");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101704");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101703");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101706");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101725");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101727");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101722");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101737");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101707");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101741");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101709");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101751");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101753");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101716");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101723");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101748");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101732");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101742");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101731");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101730");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win10:1, win10x64:1) <= 0){
  exit(0);
}

Path = smb_get_system32root();
if(!Path ){
  exit(0);
}

edgeVer = fetch_file_version(sysPath:Path, file_name:"edgehtml.dll");
if(!edgeVer){
  exit(0);
}

if(version_in_range(version:edgeVer, test_version:"11.0.16299.0", test_version2:"11.0.16299.63"))
{
  report = report_fixed_ver( file_checked:Path + "\Edgehtml.dll",
                             file_version:edgeVer, vulnerable_range:"11.0.16299.0 - 11.0.16299.63" );
  security_message(data:report);
  exit(0);
}
exit(0);

###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Multiple Vulnerabilities (KB4088875)
#
# Authors:
# Rajat Mishra <rajatm@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.812829");
  script_version("2022-04-13T07:21:45+0000");
  script_cve_id("CVE-2018-0811", "CVE-2018-0813", "CVE-2018-0814", "CVE-2018-0815",
                "CVE-2018-0886", "CVE-2018-0888", "CVE-2018-0889", "CVE-2018-0891",
                "CVE-2018-0894", "CVE-2018-0895", "CVE-2018-0896", "CVE-2018-0897",
                "CVE-2018-0898", "CVE-2018-0899", "CVE-2018-0900", "CVE-2018-0901",
                "CVE-2018-0904", "CVE-2018-0927", "CVE-2018-0929", "CVE-2018-0932",
                "CVE-2018-0935", "CVE-2018-0942", "CVE-2018-0816", "CVE-2018-0817",
                "CVE-2018-0868", "CVE-2018-0878", "CVE-2018-0881", "CVE-2018-0883",
                "CVE-2018-0885");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-13 07:21:45 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-13 13:45:00 +0000 (Wed, 13 Mar 2019)");
  script_tag(name:"creation_date", value:"2018-03-14 09:52:01 +0530 (Wed, 14 Mar 2018)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4088875)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4088875");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - When Windows Hyper-V on a host operating system fails to properly validate
    input from an authenticated user on a guest operating system.

  - The way that the scripting engine handles objects in memory in Internet
    Explorer.

  - When Microsoft Hyper-V Network Switch on a host server fails to properly
    validate input from a privileged user on a guest operating system.

  - The Credential Security Support Provider protocol (CredSSP).

  - Windows when the Microsoft Video Control mishandles objects in memory.

  - When Windows Shell does not properly validate file copy destinations.

  - When Internet Explorer fails a check, allowing sandbox escape.

  - The Windows kernel that could allow an attacker to retrieve information
    that could lead to a Kernel Address Space Layout Randomization (ASLR) bypass.

  - The Windows Installer when the Windows Installer fails to properly sanitize
    input leading to an insecure library loading behavior.

  - When the Windows kernel improperly initializes objects in memory.

  - When Windows Remote Assistance incorrectly processes XML External Entities
    (XXE).

  - The way that the Windows Graphics Device Interface (GDI) handles objects in
    memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to gain access to information, crash server and run arbitrary code in system
  mode.");

  script_tag(name:"affected", value:"- Microsoft Windows 7 for 32-bit/x64 Systems Service Pack 1

  - Microsoft Windows Server 2008 R2 for x64-based Systems Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4088875");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103232");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103250");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103251");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103234");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103265");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103262");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103295");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103309");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103231");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103238");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103240");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103241");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103242");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103243");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103244");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103245");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103246");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103310");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103299");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103307");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103298");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103312");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103248");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103249");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103236");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103230");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103256");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103259");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103261");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:sysPath, file_name:"win32k.sys");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"6.1.7601.24059"))
{
  report = report_fixed_ver(file_checked:sysPath + "\win32k.sys",
  file_version:fileVer, vulnerable_range:"Less than 6.1.7601.24059");
  security_message(data:report);
  exit(0);
}
exit(0);

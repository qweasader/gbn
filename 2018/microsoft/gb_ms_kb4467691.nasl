###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Multiple Vulnerabilities (KB4467691)
#
# Authors:
# Vidita V Koushik <vidita@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.814341");
  script_version("2021-06-23T02:00:29+0000");
  script_cve_id("CVE-2018-8256", "CVE-2018-8407", "CVE-2018-8408", "CVE-2018-8415",
                "CVE-2018-8417", "CVE-2018-8450", "CVE-2018-8471", "CVE-2018-8476",
                "CVE-2018-8485", "CVE-2018-8542", "CVE-2018-8543", "CVE-2018-8544",
                "CVE-2018-8547", "CVE-2018-8549", "CVE-2018-8553", "CVE-2018-8555",
                "CVE-2018-8556", "CVE-2018-8557", "CVE-2018-8561", "CVE-2018-8562",
                "CVE-2018-8564", "CVE-2018-8565", "CVE-2018-8584", "CVE-2018-8588",
                "CVE-2018-8550", "CVE-2018-8552", "CVE-2018-3639");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-06-23 02:00:29 +0000 (Wed, 23 Jun 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-13 19:15:00 +0000 (Thu, 13 Feb 2020)");
  script_tag(name:"creation_date", value:"2018-11-14 12:28:34 +0530 (Wed, 14 Nov 2018)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4467691)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4467691");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - PowerShell improperly handles specially crafted files.

  - Kernel Remote Procedure Call Provider driver improperly initializes objects
    in memory.

  - Windows kernel improperly initializes objects in memory.

  - PowerShell allows an attacker to execute unlogged code.

  - Microsoft JScript improperly manages COM object creation.

  - Windows Search improperly handles objects in memory.

  - Microsoft RemoteFX Virtual GPU miniport driver improperly handles objects in
    memory.

  - Windows Deployment Services TFTP Server improperly handles objects in memory.

  - DirectX improperly handles objects in memory.

  - Chakra scripting engine improperly handles objects in memory in Microsoft Edge.

  - VBScript engine improperly handles objects in memory.

  - open source customization for AD FS improper sanitization of web requests.

  - Windows incorrectly validates kernel driver signatures.

  - Windows COM Marshaler incorrectly processes interface requests.

  - Microsoft Graphics Components improperly handles objects in memory.

  - Win32k component fails to properly handle objects in memory.

  - Microsoft Edge improperly handles specific HTML content.

  - Windows improperly handles calls to ALPC.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to run arbitrary code, bypass security restrictions and load improperly signed
  drivers into the kernel, gain the same user rights as the current user, obtain
  information to further compromise the user's system, improperly discloses file
  information, trick a user into believing that the user was on a legitimate website
  and escalate privileges.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 1607 for 32/64-bit Systems

  - Microsoft Windows Server 2016");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4467691");
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

if(hotfix_check_sp(win10:1, win10x64:1, win2016:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

edgeVer = fetch_file_version(sysPath:sysPath, file_name:"edgehtml.dll");
if(!edgeVer){
  exit(0);
}

if(version_in_range(version:edgeVer, test_version:"11.0.14393.0", test_version2:"11.0.14393.2607"))
{
  report = report_fixed_ver(file_checked:sysPath + "\Edgehtml.dll",
                            file_version:edgeVer, vulnerable_range:"11.0.14393.0 - 11.0.14393.2607");
  security_message(data:report);
  exit(0);
}
exit(99);

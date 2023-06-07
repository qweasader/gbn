# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.817691");
  script_version("2021-08-25T14:01:09+0000");
  script_cve_id("CVE-2021-26413", "CVE-2021-26415", "CVE-2021-27072", "CVE-2021-27089",
                "CVE-2021-27093", "CVE-2021-27094", "CVE-2021-27095", "CVE-2021-27096",
                "CVE-2021-28309", "CVE-2021-28315", "CVE-2021-28316", "CVE-2021-28317",
                "CVE-2021-28318", "CVE-2021-28323", "CVE-2021-28325", "CVE-2021-28327",
                "CVE-2021-28328", "CVE-2021-28329", "CVE-2021-28330", "CVE-2021-28331",
                "CVE-2021-28332", "CVE-2021-28333", "CVE-2021-28334", "CVE-2021-28335",
                "CVE-2021-28336", "CVE-2021-28337", "CVE-2021-28338", "CVE-2021-28339",
                "CVE-2021-28340", "CVE-2021-28341", "CVE-2021-28342", "CVE-2021-28343",
                "CVE-2021-28344", "CVE-2021-28345", "CVE-2021-28346", "CVE-2021-28348",
                "CVE-2021-28349", "CVE-2021-28350", "CVE-2021-28352", "CVE-2021-28353",
                "CVE-2021-28354", "CVE-2021-28355", "CVE-2021-28356", "CVE-2021-28357",
                "CVE-2021-28358", "CVE-2021-28434", "CVE-2021-28435", "CVE-2021-28437",
                "CVE-2021-28439", "CVE-2021-28440", "CVE-2021-28443", "CVE-2021-28444",
                "CVE-2021-28445", "CVE-2021-28446", "CVE-2021-28447");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-08-25 14:01:09 +0000 (Wed, 25 Aug 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-15 18:34:00 +0000 (Thu, 15 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-14 11:09:15 +0530 (Wed, 14 Apr 2021)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5001382)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB5001382");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple errors in Windows Installer.

  - An error in Microsoft 'Win32k' component.

  - An error in Windows Media Photo Codec component.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to perform remote code execution, conduct a denial-of-service condition, gain
  access to potentially sensitive data, bypass security restrictions, conduct spoofing
  and elevate privileges.");

  script_tag(name:"affected", value:"- Microsoft Windows 8.1 for 32-bit/x64-based systems

  - Microsoft Windows Server 2012 R2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5001382");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
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

if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) <= 0){
  exit(0);
}

dllPath = smb_get_system32root();
if(!dllPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:dllPath, file_name:"ntoskrnl.exe");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"6.3.9600.19994"))
{
  report = report_fixed_ver(file_checked:dllPath + "\Ntoskrnl.exe",
                            file_version:fileVer, vulnerable_range:"Less than 6.3.9600.19994");
  security_message(data:report);
  exit(0);
}
exit(99);

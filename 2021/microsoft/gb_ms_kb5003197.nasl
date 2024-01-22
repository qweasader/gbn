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
  script_oid("1.3.6.1.4.1.25623.1.0.818112");
  script_version("2023-10-20T16:09:12+0000");
  script_cve_id("CVE-2020-24587", "CVE-2020-24588", "CVE-2020-26144", "CVE-2021-26419",
                "CVE-2021-28455", "CVE-2021-28476", "CVE-2021-28479", "CVE-2021-31182",
                "CVE-2021-31184", "CVE-2021-31186", "CVE-2021-31187", "CVE-2021-31188",
                "CVE-2021-31193", "CVE-2021-31194");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-20 16:09:12 +0000 (Fri, 20 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-14 17:15:00 +0000 (Wed, 14 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-05-12 11:26:06 +0530 (Wed, 12 May 2021)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5003197)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB5003197");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple errors in Windows Installer.

  - An error in Microsoft 'Win32k' component.

  - An error in Windows Media Photo Codec component.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to perform remote code execution and conduct spoofing attacks.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 1607 for 32-bit Systems

  - Microsoft Windows 10 Version 1607 for x64-based Systems

  - Microsoft Windows Server 2016");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5003197");
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

if(hotfix_check_sp(win10:1, win10x64:1, win2016:1) <= 0){
  exit(0);
}

dllPath = smb_get_system32root();
if(!dllPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:dllPath, file_name:"Pcadm.dll");
if(!fileVer){
  exit(0);
}

if(version_in_range(version:fileVer, test_version:"10.0.14393.0", test_version2:"10.0.14393.4401"))
{
  report = report_fixed_ver(file_checked:dllPath + "\Pcadm.dll",
                            file_version:fileVer, vulnerable_range:"10.0.14393.0 - 10.0.14393.4401");
  security_message(data:report);
  exit(0);
}
exit(99);

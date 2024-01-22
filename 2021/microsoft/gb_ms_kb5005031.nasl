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
  script_oid("1.3.6.1.4.1.25623.1.0.817742");
  script_version("2024-01-01T05:05:52+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2021-26424", "CVE-2021-26425", "CVE-2021-26426", "CVE-2021-26432",
                "CVE-2021-26433", "CVE-2021-34480", "CVE-2021-34483", "CVE-2021-34484",
                "CVE-2021-34486", "CVE-2021-34487", "CVE-2021-34530", "CVE-2021-34533",
                "CVE-2021-34534", "CVE-2021-34535", "CVE-2021-34536", "CVE-2021-34537",
                "CVE-2021-36926", "CVE-2021-36932", "CVE-2021-36933", "CVE-2021-36936",
                "CVE-2021-36937", "CVE-2021-36947", "CVE-2021-36948", "CVE-2021-34481");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-01-01 05:05:52 +0000 (Mon, 01 Jan 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-28 20:15:00 +0000 (Thu, 28 Dec 2023)");
  script_tag(name:"creation_date", value:"2021-08-11 13:16:04 +0530 (Wed, 11 Aug 2021)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5005031)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB5005031");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error in Windows TCP/IP Driver.

  - An error in Windows InstallService.

  - An error in Windows Kernel.

  - An error in Windows Projected File System.

  - An error in Windows Secure Kernel Mode.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to conduct DoS, bypass security restrictions, perform remote code execution,
  gain access to potentially sensitive data, conduct spoofing and elevate privileges.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 1909 for 32-bit Systems

  - Microsoft Windows 10 Version 1909 for x64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5005031");
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

if(hotfix_check_sp(win10:1, win10x64:1) <= 0){
  exit(0);
}

dllPath = smb_get_system32root();
if(!dllPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:dllPath, file_name:"spoolsv.exe");
if(!fileVer){
  exit(0);
}

if(version_in_range(version:fileVer, test_version:"10.0.18362.0", test_version2:"10.0.18362.1733"))
{
  report = report_fixed_ver(file_checked:dllPath + "\spoolsv.exe",
                            file_version:fileVer, vulnerable_range:"10.0.18362.0 - 10.0.18362.1733");
  security_message(data:report);
  exit(0);
}
exit(99);

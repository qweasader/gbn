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
  script_oid("1.3.6.1.4.1.25623.1.0.817724");
  script_version("2024-01-01T05:05:52+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2021-31183", "CVE-2021-31979", "CVE-2021-33745", "CVE-2021-33746",
                "CVE-2021-33749", "CVE-2021-33750", "CVE-2021-33752", "CVE-2021-33754",
                "CVE-2021-33756", "CVE-2021-33757", "CVE-2021-33764", "CVE-2021-33765",
                "CVE-2021-33780", "CVE-2021-33782", "CVE-2021-33783", "CVE-2021-33786",
                "CVE-2021-33788", "CVE-2021-34440", "CVE-2021-34441", "CVE-2021-34442",
                "CVE-2021-34444", "CVE-2021-34446", "CVE-2021-34447", "CVE-2021-34448",
                "CVE-2021-34456", "CVE-2021-34457", "CVE-2021-34476", "CVE-2021-34492",
                "CVE-2021-34494", "CVE-2021-34496", "CVE-2021-34497", "CVE-2021-34498",
                "CVE-2021-34499", "CVE-2021-34500", "CVE-2021-34504", "CVE-2021-34507",
                "CVE-2021-34511", "CVE-2021-34514", "CVE-2021-34516");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-01-01 05:05:52 +0000 (Mon, 01 Jan 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-28 23:15:00 +0000 (Thu, 28 Dec 2023)");
  script_tag(name:"creation_date", value:"2021-07-14 12:39:17 +0530 (Wed, 14 Jul 2021)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5004289)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB5004289");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An elevation of privilege vulnerability in Windows Common Log File System Driver.

  - A security feature bypass vulnerability in Kerberos AppContainer.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to perform remote code execution, gain access to potentially sensitive data,
  conduct spoofing and elevate privileges.");

  script_tag(name:"affected", value:"- Microsoft Windows Server 2008 R2 for x64-based Systems Service Pack 1

  - Microsoft Windows 7 for x64-based Systems Service Pack 1

  - Microsoft Windows 7 for 32-bit Systems Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5004289");
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

if(hotfix_check_sp(win2008r2:2, win7x64:2, win7:2) <= 0){
  exit(0);
}

dllPath = smb_get_system32root();
if(!dllPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:dllPath, file_name:"advapi32.dll");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"6.1.7601.25661"))
{
  report = report_fixed_ver(file_checked:dllPath + "\advapi32.dll",
                            file_version:fileVer, vulnerable_range:"Less than 6.1.7601.25661");
  security_message(data:report);
  exit(0);
}
exit(99);

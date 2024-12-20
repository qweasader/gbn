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
  script_oid("1.3.6.1.4.1.25623.1.0.818529");
  script_version("2024-01-01T05:05:52+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2021-26435", "CVE-2021-36954", "CVE-2021-36955", "CVE-2021-36959",
                "CVE-2021-36960", "CVE-2021-36961", "CVE-2021-36962", "CVE-2021-36963",
                "CVE-2021-36964", "CVE-2021-36965", "CVE-2021-36966", "CVE-2021-36967",
                "CVE-2021-36969", "CVE-2021-36972", "CVE-2021-36973", "CVE-2021-36974",
                "CVE-2021-36975", "CVE-2021-38624", "CVE-2021-38628", "CVE-2021-38629",
                "CVE-2021-38630", "CVE-2021-38632", "CVE-2021-38633", "CVE-2021-38634",
                "CVE-2021-38635", "CVE-2021-38636", "CVE-2021-38637", "CVE-2021-38638",
                "CVE-2021-38639", "CVE-2021-38667", "CVE-2021-38671", "CVE-2021-40444",
                "CVE-2021-40447", "CVE-2021-36958");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-01-01 05:05:52 +0000 (Mon, 01 Jan 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:H/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-28 20:16:00 +0000 (Thu, 28 Dec 2023)");
  script_tag(name:"creation_date", value:"2021-09-15 10:25:29 +0530 (Wed, 15 Sep 2021)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5005565)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB5005565");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error in Windows Storage.

  - An elevation of privilege vulnerability in Windows Print Spooler.

  - A spoofing vulnerability in Windows Authenticode.

  - An elevation of privilege vulnerability in Windows Common Log File System Driver.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to disclose sensitive information, perform remote code execution, cause
  denial of service condition, conduct spoofing and elevate privileges.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 2004 for 32-bit Systems

  - Microsoft Windows 10 Version 2004 for x64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5005565");
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

fileVer = fetch_file_version(sysPath:dllPath, file_name:"pcadm.dll");
if(!fileVer){
  exit(0);
}

if(version_in_range(version:fileVer, test_version:"10.0.19041.0", test_version2:"10.0.19041.1201"))
{
  report = report_fixed_ver(file_checked:dllPath + "\Pcadm.dll",
                            file_version:fileVer, vulnerable_range:"10.0.19041.0 - 10.0.19041.1201");
  security_message(data:report);
  exit(0);
}
exit(99);

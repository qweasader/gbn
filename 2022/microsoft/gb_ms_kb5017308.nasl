# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.826517");
  script_version("2023-10-19T05:05:21+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2022-26928", "CVE-2022-30170", "CVE-2022-30196", "CVE-2022-30200",
                "CVE-2022-34718", "CVE-2022-34719", "CVE-2022-34720", "CVE-2022-34721",
                "CVE-2022-34722", "CVE-2022-34725", "CVE-2022-34726", "CVE-2022-34727",
                "CVE-2022-34728", "CVE-2022-34729", "CVE-2022-34730", "CVE-2022-34731",
                "CVE-2022-34732", "CVE-2022-34733", "CVE-2022-34734", "CVE-2022-35803",
                "CVE-2022-35831", "CVE-2022-35832", "CVE-2022-35833", "CVE-2022-35834",
                "CVE-2022-35835", "CVE-2022-35836", "CVE-2022-35837", "CVE-2022-35840",
                "CVE-2022-35841", "CVE-2022-37954", "CVE-2022-37955", "CVE-2022-37956",
                "CVE-2022-37957", "CVE-2022-37958", "CVE-2022-37969", "CVE-2022-38004",
                "CVE-2022-38005", "CVE-2022-38006");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-19 05:05:21 +0000 (Thu, 19 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-13 20:43:00 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-14 10:03:13 +0530 (Wed, 14 Sep 2022)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5017308)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5017308");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An elevation of privilege vulnerability in Windows Common Log File System Driver.

  - A information disclosure vulnerability in SPNEGO Extended Negotiation (NEGOEX) Security Mechanism.

  - A elevation of privilege vulnerability in Windows Distributed File System (DFS).

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to elevate privileges, execute arbitrary commands, disclose
  information, bypass security restrictions and conduct DoS attacks.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 20H2 for 32-bit Systems

  - Microsoft Windows 10 Version 20H2 for x64-based Systems

  - Microsoft Windows 10 Version 21H1 for 32-bit Systems

  - Microsoft Windows 10 Version 21H1 for x64-based Systems

  - Microsoft Windows 10 Version 21H2 for 32-bit Systems

  - Microsoft Windows 10 Version 21H2 for x64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5017308");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
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

key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion";
if(!registry_key_exists(key:key)){
  exit(0);
}

build = registry_get_sz(key:key, item:"CurrentBuild");
if(!build){
  exit(0);
}

if(!("19042" >< build || "19043" >< build || "19044" >< build)){
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

if(fileVer =~ "^10\.0\.19041")
{
  if(version_in_range(version:fileVer, test_version:"10.0.19041.0", test_version2:"10.0.19041.2005"))
  {
    report = report_fixed_ver(file_checked:dllPath + "\Ntoskrnl.exe",
                              file_version:fileVer, vulnerable_range:"10.0.19041.0 - 10.0.19041.2005");
    security_message(data:report);
    exit(0);
  }
}
exit(99);

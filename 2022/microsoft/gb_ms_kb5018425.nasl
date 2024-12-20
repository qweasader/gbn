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
  script_oid("1.3.6.1.4.1.25623.1.0.826495");
  script_version("2023-10-19T05:05:21+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2022-22035", "CVE-2022-24504", "CVE-2022-30198", "CVE-2022-33634",
                "CVE-2022-33635", "CVE-2022-33645", "CVE-2022-35770", "CVE-2022-37965",
                "CVE-2022-37975", "CVE-2022-37977", "CVE-2022-37978", "CVE-2022-37981",
                "CVE-2022-37982", "CVE-2022-37984", "CVE-2022-37985", "CVE-2022-37986",
                "CVE-2022-37987", "CVE-2022-37988", "CVE-2022-37989", "CVE-2022-37990",
                "CVE-2022-37991", "CVE-2022-37993", "CVE-2022-37994", "CVE-2022-37996",
                "CVE-2022-37997", "CVE-2022-37999", "CVE-2022-38000", "CVE-2022-38022",
                "CVE-2022-38026", "CVE-2022-38027", "CVE-2022-38028", "CVE-2022-38029",
                "CVE-2022-38031", "CVE-2022-38032", "CVE-2022-38033", "CVE-2022-38034",
                "CVE-2022-38037", "CVE-2022-38038", "CVE-2022-38040", "CVE-2022-38041",
                "CVE-2022-38042", "CVE-2022-38043", "CVE-2022-38044", "CVE-2022-38045",
                "CVE-2022-38047", "CVE-2022-38051", "CVE-2022-41033", "CVE-2022-41081");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-19 05:05:21 +0000 (Thu, 19 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-05 20:23:00 +0000 (Mon, 05 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-10-12 10:26:04 +0530 (Wed, 12 Oct 2022)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5018425)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB5018425");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An elevation of privilege vulnerability in Windows Print Spooler.

  - A Denial of Service vulnerability in Windows Point-to-Point Tunneling
  Protocol.

  - A remote code execution vulnerability in Windows Point-to-Point Tunneling
  Protocol.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to elevate privileges, execute arbitrary commands, disclose
  information, bypass security restrictions, spoofing and conduct DoS
  attacks.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 for 32-bit Systems

  - Microsoft Windows 10 for x64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5018425");
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

dllPath = smb_get_system32root();
if(!dllPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:dllPath, file_name:"ntoskrnl.exe");
if(!fileVer){
  exit(0);
}

if(version_in_range(version:fileVer, test_version:"10.0.10240.0", test_version2:"10.0.10240.19506"))
{
  report = report_fixed_ver(file_checked:dllPath + "\Ntoskrnl.exe",
                            file_version:fileVer, vulnerable_range:"10.0.10240.0 - 10.0.10240.19506");
  security_message(data:report);
  exit(0);
}
exit(99);

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
  script_oid("1.3.6.1.4.1.25623.1.0.817790");
  script_version("2023-10-19T05:05:21+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2022-30133", "CVE-2022-30194", "CVE-2022-34690", "CVE-2022-34691",
                "CVE-2022-34701", "CVE-2022-34702", "CVE-2022-34706", "CVE-2022-34707",
                "CVE-2022-34708", "CVE-2022-34713", "CVE-2022-34714", "CVE-2022-35743",
                "CVE-2022-35744", "CVE-2022-35745", "CVE-2022-35747", "CVE-2022-35750",
                "CVE-2022-35751", "CVE-2022-35752", "CVE-2022-35753", "CVE-2022-35756",
                "CVE-2022-35758", "CVE-2022-35759", "CVE-2022-35760", "CVE-2022-35767",
                "CVE-2022-35768", "CVE-2022-35769", "CVE-2022-35793", "CVE-2022-35795",
                "CVE-2022-35820", "CVE-2022-34689");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-19 05:05:21 +0000 (Thu, 19 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-01 01:17:00 +0000 (Thu, 01 Jun 2023)");
  script_tag(name:"creation_date", value:"2022-08-10 09:29:23 +0530 (Wed, 10 Aug 2022)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5016676)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5016676");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An elevation of privilege vulnerability in Active Directory Domain Services.

  - A Remote Code Execution Vulnerability in Windows Point-to-Point Protocol.

  - A Denial of Service Vulnerability in Windows Point-to-Point Protocol.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to elevate privileges, execute arbitrary commands, disclose
  information and conduct DoS attacks.");

  script_tag(name:"affected", value:"- Microsoft Windows 7 for 32-bit Systems Service Pack 1

  - Microsoft Windows 7 for x64-based Systems Service Pack 1

  - Microsoft Windows Server 2008 R2 for x64-based Systems Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5016676");
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

if(hotfix_check_sp(win2008r2:2, win7x64:2, win7:2) <= 0){
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

if(version_in_range(version:fileVer, test_version:"6.1.7601.0", test_version2:"6.1.7601.26062"))
{
  report = report_fixed_ver(file_checked:dllPath + "\Ntoskrnl.exe",
                            file_version:fileVer, vulnerable_range:"6.1.7601.0 - 6.1.7601.26062");
  security_message(data:report);
  exit(0);
}
exit(99);

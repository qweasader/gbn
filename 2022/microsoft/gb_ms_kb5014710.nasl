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
  script_oid("1.3.6.1.4.1.25623.1.0.817780");
  script_version("2022-08-29T10:21:34+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2022-21123", "CVE-2022-21125", "CVE-2022-21127", "CVE-2022-21166",
                "CVE-2022-30139", "CVE-2022-30140", "CVE-2022-30141", "CVE-2022-30142",
                "CVE-2022-30143", "CVE-2022-30146", "CVE-2022-30147", "CVE-2022-30149",
                "CVE-2022-30151", "CVE-2022-30152", "CVE-2022-30153", "CVE-2022-30155",
                "CVE-2022-30160", "CVE-2022-30161", "CVE-2022-30162", "CVE-2022-30163",
                "CVE-2022-30164", "CVE-2022-30166", "CVE-2022-30190");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-08-29 10:21:34 +0000 (Mon, 29 Aug 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-25 02:37:00 +0000 (Sat, 25 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-06-15 08:34:34 +0530 (Wed, 15 Jun 2022)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5014710)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5014710");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An elevation of privilege vulnerability in Windows Advanced
  Local Procedure Call.

  - A Remote Code Execution Vulnerability in Windows Hyper-V.

  - A Denial of Service Vulnerability in Windows Kernel.

  The flaw in the Microsoft Windows Support Diagnostic Tool (MSDT) and tracked via CVE-2022-30190 is
  dubbed 'Follina'.

  Please see the references for more information about the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to elevate privileges, execute arbitrary commands, disclose
  information, bypass security restrictions and conduct DoS attacks.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 for 32-bit Systems

  - Microsoft Windows 10 for x64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5014710");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2022-30190");
  script_xref(name:"URL", value:"https://msrc-blog.microsoft.com/2022/05/30/guidance-for-cve-2022-30190-microsoft-support-diagnostic-tool-vulnerability/");
  script_xref(name:"URL", value:"https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e");
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

if(hotfix_check_sp(win10:1, win10x64:1) <= 0)
  exit(0);

if(!dllPath = smb_get_system32root())
  exit(0);

if(!fileVer = fetch_file_version(sysPath:dllPath, file_name:"ntoskrnl.exe"))
  exit(0);

if(version_in_range(version:fileVer, test_version:"10.0.10240.0", test_version2:"10.0.10240.19324")) {
  report = report_fixed_ver(file_checked:dllPath + "\Ntoskrnl.exe",
                            file_version:fileVer, vulnerable_range:"10.0.10240.0 - 10.0.10240.19324");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

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
  script_oid("1.3.6.1.4.1.25623.1.0.821110");
  script_version("2023-10-19T05:05:21+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2022-21972", "CVE-2022-22011", "CVE-2022-22012", "CVE-2022-22013",
                "CVE-2022-22014", "CVE-2022-22015", "CVE-2022-22019", "CVE-2022-23270",
                "CVE-2022-26923", "CVE-2022-26925", "CVE-2022-26926", "CVE-2022-26930",
                "CVE-2022-26931", "CVE-2022-26933", "CVE-2022-26934", "CVE-2022-26935",
                "CVE-2022-26936", "CVE-2022-26937", "CVE-2022-29102", "CVE-2022-29103",
                "CVE-2022-29104", "CVE-2022-29105", "CVE-2022-29112", "CVE-2022-29114",
                "CVE-2022-29115", "CVE-2022-29120", "CVE-2022-29121", "CVE-2022-29122",
                "CVE-2022-29123", "CVE-2022-29125", "CVE-2022-29126", "CVE-2022-29127",
                "CVE-2022-29128", "CVE-2022-29129", "CVE-2022-29130", "CVE-2022-29132",
                "CVE-2022-29134", "CVE-2022-29135", "CVE-2022-29137", "CVE-2022-29138",
                "CVE-2022-29139", "CVE-2022-29141", "CVE-2022-29150", "CVE-2022-29151");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-19 05:05:21 +0000 (Thu, 19 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-17 20:56:00 +0000 (Tue, 17 May 2022)");
  script_tag(name:"creation_date", value:"2022-05-11 12:26:14 +0530 (Wed, 11 May 2022)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5014011)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5014011");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An elevation of privilege vulnerability in Windows Kerberos.

  - A Remote Code Execution Vulnerability in Windows Network File System.

  - A Denial of Service Vulnerability in Windows WLAN AutoConfig Service.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to elevate privileges, execute arbitrary commands, disclose information,
  bypass security restrictions, conduct spoofing attacks and conduct DoS attacks.");

  script_tag(name:"affected", value:"- Microsoft Windows 8.1 for 32-bit/x64-based systems

  - Microsoft Windows Server 2012 R2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5014011");
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

if(version_is_less(version:fileVer, test_version:"6.3.9600.20369"))
{
  report = report_fixed_ver(file_checked:dllPath + "\Ntoskrnl.exe",
                            file_version:fileVer, vulnerable_range:"Less than 6.3.9600.20369");
  security_message(data:report);
  exit(0);
}
exit(99);

# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.815490");
  script_version("2022-08-09T10:11:17+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2019-0608", "CVE-2019-1060", "CVE-2019-1166", "CVE-2019-1192",
                "CVE-2019-1238", "CVE-2019-1311", "CVE-2019-1315", "CVE-2019-1318",
                "CVE-2019-1319", "CVE-2019-1325", "CVE-2019-1326", "CVE-2019-1333",
                "CVE-2019-1334", "CVE-2019-1339", "CVE-2019-1341", "CVE-2019-1342",
                "CVE-2019-1343", "CVE-2019-1344", "CVE-2019-1346", "CVE-2019-1347",
                "CVE-2019-1357", "CVE-2019-1358", "CVE-2019-1359", "CVE-2019-1365",
                "CVE-2019-1367", "CVE-2019-1371");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-11 19:57:00 +0000 (Fri, 11 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-10-09 10:13:33 +0530 (Wed, 09 Oct 2019)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4520005)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4520005");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Microsoft Browsers does not properly parse HTTP content.

  - Microsoft XML Core Services MSXML parser processes user input.

  - A tampering vulnerability exists in Microsoft Windows when a man-in-the-middle
    attacker is able to successfully bypass the NTLM MIC (Message Integrity Check)
    protection.

  - An error in windows redirected drive buffering system (rdbss.sys) when the
    operating system improperly handles specific local calls.

  - Windows Error Reporting (WER) improperly handles and executes files.

  - Windows Error Reporting manager improperly handles hard links.

  - Remote Desktop Protocol (RDP) improperly handles connection requests.

  - Windows Code Integrity Module improperly handles objects in memory.

  - Windows Jet Database Engine improperly handles objects in memory.

  Please see the references for more information about the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to run arbitrary code on the client machine, bypass security restrictions,
  elevate privileges and read privileged data across trust boundaries, create a
  denial of service condition and conduct spoofing attack.");

  script_tag(name:"affected", value:"- Microsoft Windows 8.1 for 32-bit/x64-based systems

  - Microsoft Windows Server 2012 R2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4520005");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
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

sysPath = smb_get_system32root();
if(!sysPath)
  exit(0);

dllVer = fetch_file_version(sysPath:sysPath, file_name:"Urlmon.dll");
if(!dllVer)
  exit(0);

if(version_is_less(version:dllVer, test_version:"11.0.9600.19507")) {
  report = report_fixed_ver(file_checked:sysPath + "\Urlmon.dll",
                            file_version:dllVer, vulnerable_range:"Less than 11.0.9600.19507");
  security_message(data:report);
  exit(0);
}

exit(99);

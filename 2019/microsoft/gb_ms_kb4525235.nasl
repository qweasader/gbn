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
  script_oid("1.3.6.1.4.1.25623.1.0.815839");
  script_version("2022-08-09T10:11:17+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2018-12207", "CVE-2019-0712", "CVE-2019-0719", "CVE-2019-11135",
                "CVE-2019-1382", "CVE-2019-1384", "CVE-2019-1388", "CVE-2019-1389",
                "CVE-2019-1390", "CVE-2019-1391", "CVE-2019-1393", "CVE-2019-1394",
                "CVE-2019-1395", "CVE-2019-1396", "CVE-2019-1397", "CVE-2019-1399",
                "CVE-2019-1405", "CVE-2019-1406", "CVE-2019-1407", "CVE-2019-1408",
                "CVE-2019-1409", "CVE-2019-1411", "CVE-2019-1412", "CVE-2019-1415",
                "CVE-2019-1418", "CVE-2019-1419", "CVE-2019-1422", "CVE-2019-1424",
                "CVE-2019-1429", "CVE-2019-1432", "CVE-2019-1433", "CVE-2019-1434",
                "CVE-2019-1435", "CVE-2019-1438", "CVE-2019-1439", "CVE-2019-1441",
                "CVE-2019-1456");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-11-13 09:00:35 +0530 (Wed, 13 Nov 2019)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4525235)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4525235");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the
  target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Windows improperly handles objects in memory.

  - Microsoft Hyper-V Network Switch on a host server fails to properly validate
    input from a privileged user on a guest operating system.

  - Windows kernel improperly handles objects in memory.

  - ActiveX Installer service may allow access to files without proper authentication.

  - Windows Certificate Dialog does not properly enforce user privileges.

  - VBScript engine improperly handles objects in memory.

  - The Win32k component fails to properly handle objects in memory.

  Please see the references for more information about the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code on a victim system, cause a target system to stop
  responding, obtain information to further compromise the user's system
  and gain elevated privileges.");

  script_tag(name:"affected", value:"- Microsoft Windows 7 for 32-bit/x64 Systems Service Pack 1

  - Microsoft Windows Server 2008 R2 for x64-based Systems Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4525235");
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

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) <= 0){
  exit(0);
}

dllPath = smb_get_system32root();
if(!dllPath)
  exit(0);

fileVer = fetch_file_version(sysPath:dllPath, file_name:"Advapi32.dll");
if(!fileVer)
  exit(0);

if(version_is_less(version:fileVer, test_version:"6.1.7601.24535")) {
  report = report_fixed_ver(file_checked:dllPath + "\Advapi32.dll",
                            file_version:fileVer, vulnerable_range:"Less than 6.1.7601.24535");
  security_message(data:report);
  exit(0);
}

exit(99);

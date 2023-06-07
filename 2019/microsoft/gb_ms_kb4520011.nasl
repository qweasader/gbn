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
  script_oid("1.3.6.1.4.1.25623.1.0.815486");
  script_version("2022-08-09T10:11:17+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2019-0608",
                "CVE-2019-1060", "CVE-2019-11091", "CVE-2019-1166", "CVE-2019-1192",
                "CVE-2019-1238", "CVE-2019-1307", "CVE-2019-1308", "CVE-2019-1311",
                "CVE-2019-1315", "CVE-2019-1316", "CVE-2019-1317", "CVE-2019-1318",
                "CVE-2019-1319", "CVE-2019-1325", "CVE-2019-1326", "CVE-2019-1333",
                "CVE-2019-1334", "CVE-2019-1335", "CVE-2019-1339", "CVE-2019-1341",
                "CVE-2019-1342", "CVE-2019-1343", "CVE-2019-1344", "CVE-2019-1346",
                "CVE-2019-1347", "CVE-2019-1357", "CVE-2019-1358", "CVE-2019-1359",
                "CVE-2019-1366", "CVE-2019-1367", "CVE-2019-1371");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-11 19:57:00 +0000 (Fri, 11 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-10-09 10:13:33 +0530 (Wed, 09 Oct 2019)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4520011)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4520011");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Speculative execution side channel vulnerabilities known as Microarchitectural
    Data Sampling.

  - Microsoft Browsers does not properly parse HTTP content.

  - Chakra scripting engine improperly handles objects in memory in Microsoft Edge.

  - Windows Imaging API improperly handles objects in memory.

  - The 'umpo.dll' of the Power Service, improperly handles a Registry Restore
    Key function.

  - Windows Error Reporting manager improperly handles hard links.

  - Internet Explorer improperly accesses objects in memory.

  Please see the references for more information about the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to run arbitrary code on the client machine, elevate privileges and read
  privileged data across trust boundaries, create a denial of service condition
  and conduct spoofing attack.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 for x64-based Systems

  - Microsoft Windows 10 for 32-bit Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4520011");
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

if(hotfix_check_sp(win10:1, win10x64:1) <= 0)
  exit(0);

if(!sysPath = smb_get_system32root())
  exit(0);

if(!edgeVer = fetch_file_version(sysPath:sysPath, file_name:"Edgehtml.dll"))
  exit(0);

if(version_in_range(version:edgeVer, test_version:"11.0.10240.0", test_version2:"11.0.10240.18365")) {
  report = report_fixed_ver(file_checked:sysPath + "\Edgehtml.dll",
                            file_version:edgeVer, vulnerable_range:"11.0.10240.0 - 11.0.10240.18365");
  security_message(data:report);
  exit(0);
}

exit(99);

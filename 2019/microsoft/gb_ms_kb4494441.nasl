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
  script_oid("1.3.6.1.4.1.25623.1.0.815046");
  script_version("2022-08-09T10:11:17+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2018-12126", "CVE-2018-12130", "CVE-2018-12127", "CVE-2018-11091",
                "CVE-2019-0683", "CVE-2019-0707", "CVE-2019-0725", "CVE-2019-0727",
                "CVE-2019-0733", "CVE-2019-0734", "CVE-2019-0758", "CVE-2019-0863",
                "CVE-2019-0881", "CVE-2019-0882", "CVE-2019-0884", "CVE-2019-0885",
                "CVE-2019-0886", "CVE-2019-0889", "CVE-2019-0890", "CVE-2019-0891",
                "CVE-2019-0892", "CVE-2019-0893", "CVE-2019-0894", "CVE-2019-0895",
                "CVE-2019-0896", "CVE-2019-0897", "CVE-2019-0898", "CVE-2019-0899",
                "CVE-2019-0900", "CVE-2019-0901", "CVE-2019-0902", "CVE-2019-0903",
                "CVE-2019-0911", "CVE-2019-0912", "CVE-2019-0913", "CVE-2019-0914",
                "CVE-2019-0915", "CVE-2019-0916", "CVE-2019-0917", "CVE-2019-0918",
                "CVE-2019-0921", "CVE-2019-0922", "CVE-2019-0923", "CVE-2019-0924",
                "CVE-2019-0925", "CVE-2019-0926", "CVE-2019-0927", "CVE-2019-0929",
                "CVE-2019-0930", "CVE-2019-0931", "CVE-2019-0933", "CVE-2019-0936",
                "CVE-2019-0937", "CVE-2019-0938", "CVE-2019-0940", "CVE-2019-0942",
                "CVE-2019-0961", "CVE-2019-0995");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-05-15 09:21:09 +0530 (Wed, 15 May 2019)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4494441)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4494441.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist:

  - Windows Jet Database Engine improperly handles objects in memory.

  - Chakra scripting engine improperly handles objects in memory in Microsoft Edge.

  - Windows Error Reporting (WER) improperly handles files.

  - An error in Windows Defender Application Control (WDAC) which could allow
    an attacker to bypass WDAC enforcement.

  Please see the references for more information about the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to execute arbitrary code, escalate privileges, bypass security
  restrictions and disclose sensitive information on a victim system.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 1809 for 32-bit Systems

  - Microsoft Windows 10 Version 1809 for x64-based Systems

  - Microsoft Windows Server 2019");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4494441");
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

if(hotfix_check_sp(win10:1, win10x64:1, win2019:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath)
  exit(0);

edgeVer = fetch_file_version(sysPath:sysPath, file_name:"edgehtml.dll");
if(!edgeVer)
  exit(0);

if(version_in_range(version:edgeVer, test_version:"11.0.17763.0", test_version2:"11.0.17763.502")) {
  report = report_fixed_ver(file_checked:sysPath + "\Edgehtml.dll",
                            file_version:edgeVer, vulnerable_range:"11.0.17763.0 - 11.0.17763.502");
  security_message(data:report);
  exit(0);
}

exit(99);

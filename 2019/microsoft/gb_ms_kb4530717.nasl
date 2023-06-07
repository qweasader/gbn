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
  script_oid("1.3.6.1.4.1.25623.1.0.815865");
  script_version("2021-09-06T14:01:33+0000");
  script_cve_id("CVE-2019-1453", "CVE-2019-1465", "CVE-2019-1466", "CVE-2019-1483",
                "CVE-2019-1467", "CVE-2019-1468", "CVE-2019-1469", "CVE-2019-1470",
                "CVE-2019-1472", "CVE-2019-1474", "CVE-2019-1476", "CVE-2019-1484",
                "CVE-2019-1485", "CVE-2019-1488", "CVE-2019-1471");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-09-06 14:01:33 +0000 (Mon, 06 Sep 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-12-11 09:28:10 +0530 (Wed, 11 Dec 2019)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4530717)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4530717");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Windows kernel improperly handles objects in memory.

  - Remote Desktop Protocol (RDP) improperly handles connection requests.

  - Windows AppX Deployment Service (AppXSVC) improperly handles hard links.

  - Windows AppX Deployment Server improperly handles junctions.

  Please see the references for more information about the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to crash host server, execute code with elevated permissions, obtain information
  to further compromise the user's system, escalate privileges and bypass security
  restrictions.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 1803 for 32-bit Systems

  - Microsoft Windows 10 Version 1803 for x64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4530717");
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

if(hotfix_check_sp(win10:1, win10x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath)
  exit(0);

sysVer = fetch_file_version(sysPath:sysPath, file_name:"Edgehtml.dll");
if(!sysVer)
  exit(0);

if(version_in_range(version:sysVer, test_version:"11.0.17134.0", test_version2:"11.0.17134.1183")) {
  report = report_fixed_ver(file_checked:sysPath + "\Edgehtml.dll",
                            file_version:sysVer, vulnerable_range:"11.0.17134.0 - 11.0.17134.1183");
  security_message(data:report);
  exit(0);
}

exit(99);

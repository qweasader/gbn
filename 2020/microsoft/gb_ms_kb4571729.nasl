# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.817267");
  script_version("2022-08-09T10:11:17+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2020-1337", "CVE-2020-1339", "CVE-2020-1377", "CVE-2020-1378",
                "CVE-2020-1379", "CVE-2020-1380", "CVE-2020-1383", "CVE-2020-1464",
                "CVE-2020-1467", "CVE-2020-1470", "CVE-2020-1472", "CVE-2020-1473",
                "CVE-2020-1474", "CVE-2020-1475", "CVE-2020-1477", "CVE-2020-1478",
                "CVE-2020-1484", "CVE-2020-1485", "CVE-2020-1486", "CVE-2020-1489",
                "CVE-2020-1513", "CVE-2020-1515", "CVE-2020-1516", "CVE-2020-1517",
                "CVE-2020-1518", "CVE-2020-1519", "CVE-2020-1520", "CVE-2020-1529",
                "CVE-2020-1530", "CVE-2020-1534", "CVE-2020-1535", "CVE-2020-1536",
                "CVE-2020-1537", "CVE-2020-1538", "CVE-2020-1539", "CVE-2020-1540",
                "CVE-2020-1541", "CVE-2020-1542", "CVE-2020-1543", "CVE-2020-1544",
                "CVE-2020-1545", "CVE-2020-1546", "CVE-2020-1547", "CVE-2020-1551",
                "CVE-2020-1552", "CVE-2020-1554", "CVE-2020-1557", "CVE-2020-1558",
                "CVE-2020-1562", "CVE-2020-1564", "CVE-2020-1567", "CVE-2020-1570",
                "CVE-2020-1577", "CVE-2020-1579", "CVE-2020-1584", "CVE-2020-1587");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-21 17:45:00 +0000 (Fri, 21 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-12 13:13:05 +0530 (Wed, 12 Aug 2020)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4571729)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4571729");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error when the Windows Print Spooler service improperly allows
    arbitrary writing to the file system.

  - An error when the Windows Kernel API fails to properly handle
    registry objects in memory.

  - An error when Windows Media Foundation fails to properly handle
    objects in memory.

  - An error in the way that the scripting engine handles objects
    in the memory in Internet Explorer.

  - An error in RPC if the server has Routing and Remote Access enabled.

  Please see the references for more information on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code, elevate privilges and disclose sensitive information.");

  script_tag(name:"affected", value:"- Microsoft Windows 7 for 32-bit/x64 Systems Service Pack 1

  - Microsoft Windows Server 2008 R2 for x64-based Systems Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4571729");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
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
if(!dllPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:dllPath, file_name:"Ntoskrnl.exe");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"6.1.7601.24559"))
{
  report = report_fixed_ver(file_checked:dllPath + "\Ntoskrnl.exe",
                            file_version:fileVer, vulnerable_range:"Less than 6.1.7601.24559");
  security_message(data:report);
  exit(0);
}
exit(99);

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
  script_oid("1.3.6.1.4.1.25623.1.0.817157");
  script_version("2023-10-20T16:09:12+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2020-0915", "CVE-2020-0916", "CVE-2020-0986", "CVE-2020-1160",
                "CVE-2020-1194", "CVE-2020-1196", "CVE-2020-1207", "CVE-2020-1208",
                "CVE-2020-1212", "CVE-2020-1213", "CVE-2020-1214", "CVE-2020-1215",
                "CVE-2020-1216", "CVE-2020-1219", "CVE-2020-1220", "CVE-2020-1230",
                "CVE-2020-1231", "CVE-2020-1236", "CVE-2020-1239", "CVE-2020-1246",
                "CVE-2020-1247", "CVE-2020-1251", "CVE-2020-1253", "CVE-2020-1254",
                "CVE-2020-1255", "CVE-2020-1260", "CVE-2020-1262", "CVE-2020-1263",
                "CVE-2020-1269", "CVE-2020-1270", "CVE-2020-1272", "CVE-2020-1281",
                "CVE-2020-1282", "CVE-2020-1287", "CVE-2020-1291", "CVE-2020-1299",
                "CVE-2020-1300", "CVE-2020-1301", "CVE-2020-1302", "CVE-2020-1310",
                "CVE-2020-1311", "CVE-2020-1314", "CVE-2020-1315", "CVE-2020-1317",
                "CVE-2020-1334", "CVE-2020-1348");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-20 16:09:12 +0000 (Fri, 20 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-16 13:21:00 +0000 (Tue, 16 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-10 08:52:23 +0530 (Wed, 10 Jun 2020)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4561666)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4561666");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple errors in Windows when the Windows kernel-mode driver fails to properly
    handle objects in memory.

  - An error when the Windows Background Intelligent Transfer Service (BITS)
    IIS module improperly handles uploaded content.

  - An error when Windows Modules Installer Service improperly handles class object
    members.

  - An error in the way that the VBScript engine handles objects in memory.

  - An error when the Windows kernel fails to properly handle objects in memory.

  - An error in the way Windows Error Reporting (WER) handles objects in memory.
  Please see the references for more information about the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code, elevate privilges, disclose sensitive information,
  conduct spoofing and denial of service attacks.");

  script_tag(name:"affected", value:"- Microsoft Windows 8.1 for 32-bit/x64-based systems

  - Microsoft Windows Server 2012 R2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4561666");
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

if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath)
  exit(0);

sysVer = fetch_file_version(sysPath:sysPath, file_name:"Atl.dll");
if(!sysVer)
  exit(0);

if(version_is_less(version:sysVer, test_version:"3.5.2284.0")) {
  report = report_fixed_ver(file_checked:sysPath + "\Atl.dll",
                            file_version:sysVer, vulnerable_range:"Less than 3.5.2284.0");
  security_message(data:report);
  exit(0);
}

exit(99);

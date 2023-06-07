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
  script_oid("1.3.6.1.4.1.25623.1.0.815458");
  script_version("2022-08-09T10:11:17+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2019-0787", "CVE-2019-0788", "CVE-2019-0928", "CVE-2019-1142",
                "CVE-2019-1268", "CVE-2019-1269", "CVE-2019-1270", "CVE-2019-1271",
                "CVE-2019-1208", "CVE-2019-1272", "CVE-2019-1274", "CVE-2019-1278",
                "CVE-2019-1214", "CVE-2019-1215", "CVE-2019-1216", "CVE-2019-1280",
                "CVE-2019-1282", "CVE-2019-1232", "CVE-2019-1235", "CVE-2019-1236",
                "CVE-2019-1287", "CVE-2019-1289", "CVE-2019-1290", "CVE-2019-1291",
                "CVE-2019-1240", "CVE-2019-1241", "CVE-2019-1292", "CVE-2019-1293",
                "CVE-2019-1242", "CVE-2019-1243", "CVE-2019-1300", "CVE-2019-1244",
                "CVE-2019-1245", "CVE-2019-1246", "CVE-2019-1247", "CVE-2019-1248",
                "CVE-2019-1249", "CVE-2019-1250", "CVE-2019-1252", "CVE-2019-1256",
                "CVE-2019-1267", "CVE-2019-1219", "CVE-2019-1220", "CVE-2019-1221",
                "CVE-2019-1285", "CVE-2019-1286");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-09-11 10:46:27 +0530 (Wed, 11 Sep 2019)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4516070)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4516070");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error in Windows Text Service Framework (TSF) when the TSF server process
    does not validate the source of input or commands it receives.

  - Diagnostics Hub Standard Collector Service improperly impersonates certain file
    operations.

  - Windows Common Log File System (CLFS) driver improperly handles objects in
    memory.

  - DirectX improperly handles objects in memory.

  - Windows Transaction Manager improperly handles objects in memory.

  - Windows improperly handles calls to Advanced Local Procedure Call (ALPC).

  - An elevation of privilege exists in hdAudio.

  - DirectWrite improperly discloses the contents of its memory.

  Please see the references for more information about the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to gain elevated privileges, execute code with elevated permissions, obtain
  information to further compromise the user's system and cause a target
  system to stop responding.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 for 32-bit Systems

  - Microsoft Windows 10 for x64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4516070");
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

edgeVer = fetch_file_version(sysPath:sysPath, file_name:"edgehtml.dll");
if(!edgeVer)
  exit(0);

if(version_in_range(version:edgeVer, test_version:"11.0.10240.0", test_version2:"11.0.10240.18332")) {
  report = report_fixed_ver(file_checked:sysPath + "\Edgehtml.dll",
                            file_version:edgeVer, vulnerable_range:"11.0.10240.0 - 11.0.10240.18332");
  security_message(data:report);
  exit(0);
}

exit(99);

# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.817599");
  script_version("2022-08-09T10:11:17+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2021-1692", "CVE-2021-1698", "CVE-2021-1722", "CVE-2021-1727",
                "CVE-2021-1731", "CVE-2021-1732", "CVE-2021-1734", "CVE-2021-24074",
                "CVE-2021-24075", "CVE-2021-24076", "CVE-2021-24077", "CVE-2021-24078",
                "CVE-2021-24079", "CVE-2021-24080", "CVE-2021-24081", "CVE-2021-24082",
                "CVE-2021-24083", "CVE-2021-24084", "CVE-2021-24086", "CVE-2021-24088",
                "CVE-2021-24091", "CVE-2021-24093", "CVE-2021-24094", "CVE-2021-24096",
                "CVE-2021-24098", "CVE-2021-24102", "CVE-2021-24103", "CVE-2021-24106",
                "CVE-2021-25195");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-03 18:59:00 +0000 (Wed, 03 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-02-10 11:30:27 +0530 (Wed, 10 Feb 2021)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4601319)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4601319");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error in Windows Fax Service.

  - An error in Windows Installer.

  - An error in Windows Remote Procedure Call.

  - An error in Windows TCP/IP.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to execute arbitrary code on a victim system, disclose sensitive information,
  conduct denial-of-service condition and gain elevated privileges.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 2004 for 32-bit Systems

  - Microsoft Windows 10 Version 2004 for x64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4601319");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
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

dllPath = smb_get_system32root();
if(!dllPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:dllPath, file_name:"kernel32.dll");
if(!fileVer){
  exit(0);
}

if(version_in_range(version:fileVer, test_version:"10.0.19041.0", test_version2:"10.0.19041.803"))
{
  report = report_fixed_ver(file_checked:dllPath + "\kernel32.dll",
                            file_version:fileVer, vulnerable_range:"10.0.19041.0 - 10.0.19041.803");
  security_message(data:report);
  exit(0);
}
exit(99);

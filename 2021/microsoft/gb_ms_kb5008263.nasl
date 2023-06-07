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
  script_oid("1.3.6.1.4.1.25623.1.0.818922");
  script_version("2021-12-23T12:12:57+0000");
  script_cve_id("CVE-2021-40441", "CVE-2021-41333", "CVE-2021-43207", "CVE-2021-43215",
                "CVE-2021-43216", "CVE-2021-43217", "CVE-2021-43222", "CVE-2021-43223",
                "CVE-2021-43224", "CVE-2021-43226", "CVE-2021-43229", "CVE-2021-43230",
                "CVE-2021-43232", "CVE-2021-43233", "CVE-2021-43234", "CVE-2021-43236",
                "CVE-2021-43238", "CVE-2021-43245", "CVE-2021-43248", "CVE-2021-43883",
                "CVE-2021-43893");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-12-23 12:12:57 +0000 (Thu, 23 Dec 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-22 13:24:00 +0000 (Wed, 22 Dec 2021)");
  script_tag(name:"creation_date", value:"2021-12-15 15:57:04 +0530 (Wed, 15 Dec 2021)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5008263)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB5008263");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An elevation of privilege vulnerability in Windows Encrypting File System (EFS).

  - An RCE vulnerability in Windows Encrypting File System (EFS).

  - A memory corruption vulnerability in iSNS Server.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to elevate privileges, disclose sensitive information and conduct
  remote code execution.");

  script_tag(name:"affected", value:"- Microsoft Windows 8.1 for 32-bit/x64-based systems

  - Microsoft Windows Server 2012 R2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5008263");
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

if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) <= 0){
  exit(0);
}

dllPath = smb_get_system32root();
if(!dllPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:dllPath, file_name:"cipher.exe");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"6.3.9600.20207"))
{
  report = report_fixed_ver(file_checked:dllPath + "\Cipher.exe",
                            file_version:fileVer, vulnerable_range:"Less than 6.3.9600.20207");
  security_message(data:report);
  exit(0);
}
exit(99);

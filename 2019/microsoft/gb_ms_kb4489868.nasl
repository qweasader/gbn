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
  script_oid("1.3.6.1.4.1.25623.1.0.814697");
  script_version("2022-08-09T10:11:17+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2019-0603", "CVE-2019-0609", "CVE-2019-0780", "CVE-2019-0782",
                "CVE-2019-0783", "CVE-2019-0611", "CVE-2019-0612", "CVE-2019-0614",
                "CVE-2019-0617", "CVE-2019-0784", "CVE-2019-0797", "CVE-2019-0821",
                "CVE-2019-0678", "CVE-2019-0680", "CVE-2019-0682", "CVE-2019-0689",
                "CVE-2019-0690", "CVE-2019-0692", "CVE-2019-0693", "CVE-2019-0694",
                "CVE-2019-0695", "CVE-2019-0696", "CVE-2019-0697", "CVE-2019-0698",
                "CVE-2019-0701", "CVE-2019-0702", "CVE-2019-0703", "CVE-2019-0704",
                "CVE-2019-0726", "CVE-2019-0746", "CVE-2019-0754", "CVE-2019-0755",
                "CVE-2019-0756", "CVE-2019-0759", "CVE-2019-0761", "CVE-2019-0762",
                "CVE-2019-0763", "CVE-2019-0765", "CVE-2019-0766", "CVE-2019-0767",
                "CVE-2019-0768", "CVE-2019-0769", "CVE-2019-0770", "CVE-2019-0771",
                "CVE-2019-0772", "CVE-2019-0773", "CVE-2019-0774", "CVE-2019-0775",
                "CVE-2019-0776", "CVE-2019-0639", "CVE-2019-0665", "CVE-2019-0666",
                "CVE-2019-0667", "CVE-2019-0601");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-03-13 09:20:16 +0530 (Wed, 13 Mar 2019)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4489868)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4489868");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Microsoft Edge does not properly enforce cross-domain policies.

  - An error in way scripting engine handles objects in memory in Microsoft Edge.

  - Click2Play protection in Microsoft Edge improperly handles flash objects.

  - ChakraCore scripting engine improperly handles objects in memory.

  - Windows Jet Database Engine improperly handles objects in memory.

  - Windows GDI component improperly discloses the contents of its memory.

  - Windows kernel improperly handles objects in memory.

  - The win32k component improperly provides kernel information.

  - Microsoft XML Core Services MSXML parser improperly processes user input.

  - The Win32k component fails to properly handle objects in memory.

  - Windows Print Spooler does not properly handle objects in memory.

  - An integer overflow in Windows Subsystem for Linux.

  - Microsoft Hyper-V Network Switch on a host server fails to properly
    validate input from a privileged user on a guest operating system.

  - Windows kernel fails to properly handle objects in memory.

  - Windows DHCP client does not validate specially crafted DHCP responses
    to a client.

  - Microsoft Hyper-V on a host server fails to properly validate input from
    a privileged user on a guest operating system.

  - Windows SMB Server fails to properly handle handles certain requests.

  - VBScript engine improperly handles objects in memory.

  - Windows Deployment Services TFTP Server improperly handles objects in
    memory.

  - Windows AppX Deployment Server allows file creation in arbitrary
    locations.

  - Microsoft browsers improperly handle requests of different origins.

  - Internet Explorer improperly accesses objects in memory.

  - Internet Explorer fails to validate the correct Security Zone of requests
    for specific URLs.

  - The ActiveX Data objects (ADO) improperly handles objects in memory.

  - Internet Explorer VBScript execution policy does not properly restrict
    VBScript under specific conditions, and to allow requests that should otherwise
    be ignored.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  an attacker to elevate privileges, execute arbitrary code on a victim system,
  cause a target system to stop responding and bypass security restrictions.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 1803 for 32-bit Systems

  - Microsoft Windows 10 Version 1803 for x64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4489868");
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

dllPath = smb_get_system32root();
if(!dllPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:dllPath, file_name:"Edgehtml.dll");
if(!fileVer){
  exit(0);
}

if(version_in_range(version:fileVer, test_version:"11.0.17134.0", test_version2:"11.0.17134.647"))
{
  report = report_fixed_ver(file_checked:dllPath + "\Edgehtml.dll",
                            file_version:fileVer, vulnerable_range:"11.0.17134.0 - 11.0.17134.647");
  security_message(data:report);
  exit(0);
}
exit(99);
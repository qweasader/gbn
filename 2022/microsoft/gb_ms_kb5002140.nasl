# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.819985");
  script_version("2022-02-16T03:03:58+0000");
  script_cve_id("CVE-2022-22003");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-02-16 03:03:58 +0000 (Wed, 16 Feb 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-14 21:41:00 +0000 (Mon, 14 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-09 09:09:56 +0530 (Wed, 09 Feb 2022)");
  script_name("Microsoft Office 2016 Remote Code Execution Vulnerability (KB5002140)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5002140");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an improper input validation
  in Microsoft Office Graphics.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code on the target system and may result in complete
  compromise of vulnerable system.");

  script_tag(name:"affected", value:"Microsoft Office 2016.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5002140");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver");
  script_require_ports(139, 445);
  exit(0);
}
include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

officeVer = get_kb_item("MS/Office/Ver");
if(!officeVer){
  exit(0);
}

if(officeVer =~ "^16\.")
{
  os_arch = get_kb_item("SMB/Windows/Arch");
  if("x86" >< os_arch){
    key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion");
  }
  else if("x64" >< os_arch){
    key_list =  make_list("SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion",
                          "SOFTWARE\Microsoft\Windows\CurrentVersion");
  }

  foreach key(key_list)
  {
    propath = registry_get_sz(key:key, item:"ProgramFilesDir");
    if(propath)
    {
      offPath = propath + "\Microsoft Office\root\VFS\ProgramFilesCommonX86\Microsoft Shared\Office16";
      offexeVer = fetch_file_version(sysPath:offPath, file_name:"mso.dll");
      if(!offexeVer){
        continue ;
      }

      if(offexeVer =~ "^16\." && version_is_less(version:offexeVer, test_version:"16.0.5278.1000"))
      {
        report = report_fixed_ver(file_checked:offPath + "\mso.dll",
                 file_version:offexeVer, vulnerable_range:"16.0 - 16.0.5278.0999");
        security_message(data:report);
        exit(0);
      }
    }
  }
}
exit(99);
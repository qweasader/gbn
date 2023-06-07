# Copyright (C) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.903034");
  script_version("2022-05-25T07:40:23+0000");
  script_cve_id("CVE-2012-1854");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-05-25 07:40:23 +0000 (Wed, 25 May 2022)");
  script_tag(name:"creation_date", value:"2012-07-11 12:07:45 +0530 (Wed, 11 Jul 2012)");
  script_name("Visual Basic for Applications Remote Code Execution Vulnerability (2707960)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl",
                      "smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code affected system.");

  script_tag(name:"affected", value:"- Microsoft Visual Basic for Applications

  - Microsoft Office 2003 Service Pack 3 and prior

  - Microsoft Office 2007 Service Pack 3 and prior

  - Microsoft Office 2010 Service Pack 1 and prior");

  script_tag(name:"insight", value:"Microsoft Visual Basic for Applications incorrectly restricts the path used
  for loading external libraries, which can be exploited by tricking a user to
  open a legitimate Microsoft Office related file located in the same network
  directory as a specially crafted dynamic link library (DLL) file.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS12-046.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/976321");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54303");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2598243");
  script_xref(name:"URL", value:"http://support.microsoft.com/KB/2598361");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2553447");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2688865");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/KB2598361");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-046");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
              item:"CommonFilesDir");
if(!dllPath){
  exit(0);
}

officeVer = get_kb_item("MS/Office/Ver");

dllVer6 = fetch_file_version(sysPath:dllPath,
              file_name:"Microsoft Shared\VBA\VBA6\VBE6.DLL");

if(dllVer6)
{
  if(version_is_less(version:dllVer6, test_version:"6.5.10.54"))
  {
    report = report_fixed_ver(installed_version:dllVer6, fixed_version:"6.5.10.54");
    security_message(port:0, data:report);
    exit(0);
  }
}

if(officeVer =~ "^14\..*")
{
  dllVer7 = fetch_file_version(sysPath:dllPath,
           file_name:"Microsoft Shared\VBA\VBA7\VBE7.DLL");

  if(dllVer7)
  {
    if(version_in_range(version:dllVer7, test_version:"7.0", test_version2:"7.0.16.26"))
    {
      report = report_fixed_ver(installed_version:dllVer7, vulnerable_range:"7.0 - 7.0.16.26");
      security_message(port:0, data:report);
      exit(0);
    }
  }

  accVer = fetch_file_version(sysPath:dllPath,
             file_name:"Microsoft Shared\OFFICE14\ACEES.DLL");

  if(accVer)
  {
    if(version_in_range(version:accVer, test_version:"14.0", test_version2:"14.0.6015.999")){
      report = report_fixed_ver(installed_version:accVer, vulnerable_range:"14.0 - 14.0.6015.999");
      security_message(port:0, data:report);
    }
  }
}

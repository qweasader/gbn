# Copyright (C) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.902245");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-09-15 17:01:07 +0200 (Wed, 15 Sep 2010)");
  script_cve_id("CVE-2010-2563");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("WordPad Text Converters Remote Code Execution Vulnerability (2259922)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2259922");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43122");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation of this issue may allow attackers to execute
  arbitrary code in the context of a logged-on user by tricking a user to
  open specially crafted Word 97 document.");
  script_tag(name:"affected", value:"- Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows 2003 Service Pack 2 and prior");
  script_tag(name:"insight", value:"A flaw exists in the Microsoft WordPad text converter, which incorrectly
  parses specific fields in a Word 97 document.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS10-067.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-067");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");


if(hotfix_check_sp(xp:4, win2003:3) <= 0){
  exit(0);
}

if(hotfix_missing(name:"2259922") == 0){
  exit(0);
}

progDir = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\",
                           item:"ProgramFilesDir");
if(!progDir){
  exit(0);
}
filePath = progDir + "\Windows NT\Accessories";

share = ereg_replace(pattern:"([a-zA-Z]):.*", replace:"\1$", string:filePath);
file =  ereg_replace(pattern:"[a-zA-Z]:(.*)", replace:"\1",
                     string:filePath + "\Mswrd8.wpc");

sysVer = GetVer(file:file, share:share);
if(!sysVer){
  exit(0);
}

if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 3" >< SP)
  {
    if(version_is_less(version:sysVer, test_version:"2010.6.31.10")){
      report = report_fixed_ver(installed_version:sysVer, fixed_version:"2010.6.31.10", install_path:filePath);
      security_message(port: 0, data: report);
    }
    exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

if(hotfix_check_sp(win2003:3) > 0)
{
  SP = get_kb_item("SMB/Win2003/ServicePack");
  if("Service Pack 2" >< SP)
  {
    if(version_is_less(version:sysVer, test_version:"2010.6.31.10")){
      report = report_fixed_ver(installed_version:sysVer, fixed_version:"2010.6.31.10", install_path:filePath);
      security_message(port: 0, data: report);
    }
    exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

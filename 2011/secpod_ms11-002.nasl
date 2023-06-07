# Copyright (C) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.902281");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-01-12 13:59:47 +0100 (Wed, 12 Jan 2011)");
  script_cve_id("CVE-2011-0026", "CVE-2011-0027");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Windows Data Access Components Remote Code Execution Vulnerabilities (2451910)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation will allow the attacker to execute arbitrary code on
  the targeted system.");
  script_tag(name:"affected", value:"- Microsoft Windows 7

  - Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows 2K3 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 2 and prior

  - Microsoft Windows Server 2008 Service Pack 2 and prior");
  script_tag(name:"insight", value:"The flaws are due to:

  - A buffer overflow error in the Data Source Name (DSN) argument of an Open
    Database Connectivity (ODBC) API that may be used by third-party applications,
    which could allow attackers to execute arbitrary code by convincing a user to
    visit a specially crafted web page.

  - A memory corruption error in the Microsoft Data Access Components (MDAC) when
    handling internal data structures, which could be exploited by remote attackers
    to execute arbitrary code via a specially crafted web page.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS11-002.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2419632");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45695");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45698");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2419635");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2419640");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0075");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-002");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3, win7:1) <= 0){
  exit(0);
}

## MS11-002 Hotfix 2419635 2419640 2419632
if((hotfix_missing(name:"2419635") == 0) || (hotfix_missing(name:"2419640") == 0) ||
  (hotfix_missing(name:"2419632") == 0)){
  exit(0);
}

sysPath =registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\",
                           item:"ProgramFilesDir");
if(!sysPath ){
  exit(0);
}

dllPath = sysPath + "\Common Files\System\msadc";
share = ereg_replace(pattern:"([a-zA-Z]):.*", replace:"\1$", string:dllPath);
file =  ereg_replace(pattern:"[a-zA-Z]:(.*)", replace:"\1",
                     string:dllPath + "\Msadco.dll");

dllVer = GetVer(file:file, share:share);
if(!dllVer){
  exit(0);
}

if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 3" >< SP)
  {
    if(version_is_less(version:dllVer, test_version:"2.81.3012.0")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

else if(hotfix_check_sp(win2003:3) > 0)
{
  SP = get_kb_item("SMB/Win2003/ServicePack");
  if("Service Pack 2" >< SP)
  {
    if(version_is_less(version:dllVer, test_version:"2.82.4795.0")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");

  if(!SP) {
    SP = get_kb_item("SMB/Win2008/ServicePack");
  }

  if("Service Pack 1" >< SP)
  {
    if(version_is_less(version:dllVer, test_version:"6.0.6001.18570")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    if(version_is_less(version:dllVer, test_version:"6.0.6002.18362")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

else if(hotfix_check_sp(win7:1) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.1.7600.16688")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

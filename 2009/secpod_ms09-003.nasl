# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.900079");
  script_version("2022-05-25T07:40:23+0000");
  script_tag(name:"last_modification", value:"2022-05-25 07:40:23 +0000 (Wed, 25 May 2022)");
  script_tag(name:"creation_date", value:"2009-02-11 16:51:00 +0100 (Wed, 11 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0098", "CVE-2009-0099");
  script_name("Vulnerabilities in Microsoft Exchange Could Allow Remote Code Execution (959239)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation allows remote arbitrary code execution sending
  a specially crafted MAPI command using the EMSMDB32 provider.");

  script_tag(name:"affected", value:"Microsoft Exchange Server 2000/2003/2007 on Microsoft Windows Servers.");

  script_tag(name:"insight", value:"- Error exists within the decoding of Transport Neutral Encapsulation
  Format (TNEF) data that causes memory corruption when a user opens or
  previews a specially crafted e-mail message sent in TNEF format.

  - Error exists within the processing of MAPI commands in the EMSMDB2.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS09-003.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-003");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33134");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33136");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2k:5, win2003:3) <= 0){
  exit(0);
}

appName = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                              "\Uninstall\Microsoft Exchange",
                          item:"DisplayName");
if(!appName){
  exit(0);
}

function Get_FileVersion()
{
  excFile = registry_get_sz(key:"SOFTWARE\Microsoft\Exchange\Setup",
                            item:"MsiInstallPath");
  if(!excFile){
    exit(0);
  }

  dllVer = fetch_file_version( sysPath:excFile, file_name:"\bin\Davex.dll" );
  if(!dllVer){
    return 0;
  }
  else return dllVer;
}


if("Microsoft Exchange Server 2003" >< appName)
{
  if(hotfix_missing(name:"959897") == 0){
    exit(0);
  }

  fileVer = Get_FileVersion();
  if(!fileVer){
    exit(0);
  }

  if(version_is_less(version:fileVer, test_version:"6.5.7654.12")){
    report = report_fixed_ver(installed_version:fileVer, fixed_version:"6.5.7654.12");
    security_message(port: 0, data: report);
  }
}

else if("Microsoft Exchange Server 2007" >< appName)
{
  if(hotfix_missing(name:"959241") == 0){
    exit(0);
  }

  fileVer = Get_FileVersion();
  if(!fileVer){
    exit(0);
  }

  #  Check for version < 8.01.0336.0000
  if(version_is_less(version:fileVer, test_version:"8.01.0336.0000")){
    report = report_fixed_ver(installed_version:fileVer, fixed_version:"8.01.0336.0000");
    security_message(port: 0, data: report);
  }
}

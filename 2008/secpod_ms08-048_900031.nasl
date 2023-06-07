# Copyright (C) 2008 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.900031");
  script_version("2022-05-25T07:40:23+0000");
  script_tag(name:"last_modification", value:"2022-05-25 07:40:23 +0000 (Wed, 25 May 2022)");
  script_tag(name:"creation_date", value:"2008-08-19 14:38:55 +0200 (Tue, 19 Aug 2008)");
  script_cve_id("CVE-2008-1448");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:N/A:N");
  script_category(ACT_GATHER_INFO);
  script_family("Windows : Microsoft Bulletins");
  script_name("Security Update for Outlook Express (951066)");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-048");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30585");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS08-048.");

  script_tag(name:"insight", value:"The issue is due to the MHTML protocol handler incorrectly interpreting
  MHTML URL redirections that could potentially bypass Internet Explorer
  domain restrictions when returning MHTML content.");

  script_tag(name:"affected", value:"- Outlook Express 5.5 & 6 on Windows 2000

  - Outlook Express 6 on MS Windows 2003 and XP");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"impact", value:"Remote attackers can construct a specially crafted Web page,
  achieve information disclosure, and could read data from another Internet
  Explorer domain or the local computer.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:3, win2k:5, win2003:3, win2008:2, winVista:2) <= 0)
  exit(0);

if(hotfix_missing(name:"951066") == 0)
  exit(0);

sysPath = smb_get_system32root();
if(!sysPath )
  exit(0);

dllPath = sysPath + "\inetcomm.dll";

if(!registry_key_exists(key:"SOFTWARE\Microsoft\Outlook Express"))
  exit(0);

if(hotfix_check_sp(win2k:5) > 0) {
  vers = get_version(dllPath:dllPath, string:"prod", offs:600000);
  if(vers == NULL)
    exit(0);

  # Vuln: versions < 5.50.4990.2500
  if(ereg(pattern:"^5\.50\.4999\.([01]?[0-9]?[0-9]?[0-9]|2[0-4][0-9][0-9])$", string:vers)) {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }

  # Vuln: versions < 6.0.2800.1933
  if(ereg(pattern:"^6\.0?0\.2800\.(0?[0-9]?[0-9]?[0-9]|1([0-8][0-9][0-9]|" +
        "9[0-2][0-9]|93[0-2]))$", string:vers)) {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

if(hotfix_check_sp(xp:4) > 0) {
  vers = get_version(dllPath:dllPath, string:"prod", offs:600000);
  if(vers == NULL){
    exit(0);
  }

  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 2" >< SP) {
    # Vuln: versions < 6.0.2900.3350
    if(ereg(pattern:"^6\.0?0\.2900\.([0-2]?[0-9]?[0-9]?[0-9]|3([0-2][0-9][0-9]|" +
          "3[0-4][0-9]))$", string:vers)) {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  if("Service Pack 3" >< SP) {
    # Vuln: versions < 6.0.2900.5579
    if(ereg(pattern:"^6\.0?0\.2900\.([0-4]?[0-9]?[0-9]?[0-9]|5([0-4][0-9][0-9]|" +
          "5[0-6][0-9]|57[0-8]))$", string:vers)) {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
  else security_message( port: 0, data: "The target host was found to be vulnerable" );
}

if(hotfix_check_sp(win2003:3) > 0) {
  vers = get_version(dllPath:dllPath, string:"prod", offs:600000);
  if(vers == NULL)
    exit(0);

  SP = get_kb_item("SMB/Win2003/ServicePack");
  if("Service Pack 1" >< SP) {
    # Vuln: versions < 6.0.3790.3168
    if(ereg(pattern:"^6\.0?0\.3790\.([0-2]?[0-9]?[0-9]?[0-9]|3(0[0-9][0-9]|" +
          "1[0-5][0-9]|16[0-7]))$", string:vers)) {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  if("Service Pack 2" >< SP) {
    # Vuln: versions < 6.0.3790.4325
    if(ereg(pattern:"^6\.0?0\.3790\.([0-3]?[0-9]?[0-9]?[0-9]|4([0-2][0-9][0-9]|" +
          "3[01][0-9]|32[0-4]))$", string:vers)){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
  else security_message( port: 0, data: "The target host was found to be vulnerable" );
}

dllPath = smb_get_system32root();
if(!dllPath)
  exit(0);

dllVer = fetch_file_version(sysPath:dllPath, file_name:"\inetcomm.dll");
if(dllVer) {
  if(hotfix_check_sp(winVista:2) > 0) {
    SP = get_kb_item("SMB/WinVista/ServicePack");
    if("Service Pack 1" >< SP) {
      if(version_is_less(version:dllVer, test_version:"6.0.6001.18049")) {
        report = report_fixed_ver(installed_version:dllVer, fixed_version:"6.0.6001.18049", install_path:dllPath);
        security_message(port: 0, data: report);
      }
      exit(0);
    }
  }

  else if(hotfix_check_sp(win2008:2) > 0) {
    SP = get_kb_item("SMB/Win2008/ServicePack");
    if("Service Pack 1" >< SP) {
      if(version_is_less(version:dllVer, test_version:"6.0.6001.18049")) {
        report = report_fixed_ver(installed_version:dllVer, fixed_version:"6.0.6001.18049", install_path:dllPath);
        security_message(port: 0, data: report);
      }
      exit(0);
    }
  }
}

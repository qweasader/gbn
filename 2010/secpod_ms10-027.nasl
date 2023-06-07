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
  script_oid("1.3.6.1.4.1.25623.1.0.900235");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-04-14 17:51:53 +0200 (Wed, 14 Apr 2010)");
  script_cve_id("CVE-2010-0268");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Windows Media Player Could Allow Remote Code Execution (979402)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/3938");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39351");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/979402");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-027");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code with the privileges of the user running the applications.");

  script_tag(name:"affected", value:"- Microsoft Windows Media Player 9 Series on Microsoft Windows 2K Service Pack 4 and prior

  - Microsoft Windows XP Service Pack 3 and prior");

  script_tag(name:"insight", value:"The flaw exists because Windows Media Player ActiveX control incorrectly
  handles specially crafted media content hosted on a malicious Web site.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS10-027.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2k:5, xp:4) <= 0) {
  exit(0);
}

## MS10-027 Hotfix check
if(hotfix_missing(name:"979402") == 0) {
  exit(0);
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup", item:"Install Path");
if(!sysPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sysPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:sysPath + "\wmp.dll");
windowsMediaPlayerVer = GetVer(file:file, share:share);

if(!windowsMediaPlayerVer){
  exit(0);
}

if(hotfix_check_sp(win2k:5) > 0)
{
  if(version_in_range(version:windowsMediaPlayerVer, test_version:"9", test_version2:"9.0.0.3366")) {
    report = report_fixed_ver(installed_version:windowsMediaPlayerVer, vulnerable_range:"9 - 9.0.0.3366");
    security_message(port: 0, data: report);
  }
  exit(0);
}

if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 2" >< SP)
  {
    if(version_in_range(version:windowsMediaPlayerVer, test_version:"9", test_version2:"9.0.0.3366")) {
      report = report_fixed_ver(installed_version:windowsMediaPlayerVer, vulnerable_range:"9 - 9.0.0.3366");
      security_message(port: 0, data: report);
    }
    exit(0);
  }
  else if("Service Pack 3" >< SP)
  {
    if(version_in_range(version:windowsMediaPlayerVer, test_version:"9", test_version2:"9.0.0.4507")) {
      report = report_fixed_ver(installed_version:windowsMediaPlayerVer, vulnerable_range:"9 - 9.0.0.4507");
      security_message(port: 0, data: report);
    }
    exit(0);
  }
}

###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows CSRSS CSRFinalizeContext Local Privilege Escalation Vulnerability (930178)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801719");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-01-14 09:03:25 +0100 (Fri, 14 Jan 2011)");
  script_cve_id("CVE-2006-6696", "CVE-2007-1209");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Windows CSRSS CSRFinalizeContext Local Privilege Escalation Vulnerability (930178)");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2007/Apr/1017897.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/23338");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2007/ms07-021");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute arbitrary code with
  SYSTEM privileges by establishing and closing multiple connections to the
  subsystem's ApiPort.");
  script_tag(name:"affected", value:"- Microsoft Windows XP Service Pack 2 and prior

  - Microsoft Windows 2000 ervice Pack 4 and prior

  - Microsoft Windows 2K3 Service Pack 2 and prior

  - Microsoft Windows Vista");
  script_tag(name:"insight", value:"The flaw is due to

  - A double-free error in the Client/Server Run-time Subsystem (CSRSS) within
    'WINSRV.DLL' when handling HardError messages.

  - Incorrect marshaling of system resources in the Client/Server Run-time
    Subsystem (CSRSS) when handling connections during the startup and stopping
    of processes.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS07-021.");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2k:5, xp:3, win2003:3, winVista:3) <= 0){
  exit(0);
}

if(hotfix_missing(name:"930178") == 0){
  exit(0);
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(sysPath)
{
  sysVer = fetch_file_version(sysPath:sysPath, file_name:"winsrv.dll");
  if(sysVer)
  {
    if(hotfix_check_sp(win2k:5) > 0)
    {
      if(version_is_less(version:sysVer, test_version:"5.0.2195.7135")){
        report = report_fixed_ver(installed_version:sysVer, fixed_version:"5.0.2195.7135");
        security_message(port: 0, data: report);
      }
    }

    else if(hotfix_check_sp(xp:3) > 0)
    {
      SP = get_kb_item("SMB/WinXP/ServicePack");
      if("Service Pack 2" >< SP)
      {
         if(version_is_less(version:sysVer, test_version:"5.1.2600.3103")){
          report = report_fixed_ver(installed_version:sysVer, fixed_version:"5.1.2600.3103");
          security_message(port: 0, data: report);
        }
         exit(0);
      }
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }

    else if(hotfix_check_sp(win2003:3) > 0)
    {
      SP = get_kb_item("SMB/Win2003/ServicePack");
      if("Service Pack 1" >< SP)
      {
        if(version_is_less(version:sysVer, test_version:"5.2.3790.2902")){
          report = report_fixed_ver(installed_version:sysVer, fixed_version:"5.2.3790.2902");
          security_message(port: 0, data: report);
        }
         exit(0);
      }
      if("Service Pack 2" >< SP)
      {
        if(version_is_less(version:sysVer, test_version:"5.2.3790.4043")){
          report = report_fixed_ver(installed_version:sysVer, fixed_version:"5.2.3790.4043");
          security_message(port: 0, data: report);
        }
         exit(0);
      }
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                      item:"PathName");
if(!sysPath){
  exit(0);
}

sysVer = fetch_file_version(sysPath:sysPath, file_name:"system32\winsrv.dll");
if(!sysVer){
  exit(0);
}

if(hotfix_check_sp(winVista:3) > 0)
{
  if(version_is_less(version:sysVer, test_version:"6.0.6000.16445")){
      report = report_fixed_ver(installed_version:sysVer, fixed_version:"6.0.6000.16445");
      security_message(port: 0, data: report);
  }
  exit(0);
}

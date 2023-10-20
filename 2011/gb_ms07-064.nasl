# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801710");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-01-14 07:39:17 +0100 (Fri, 14 Jan 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2007-3901", "CVE-2007-3895");
  script_name("Vulnerabilities in DirectX Could Allow Remote Code Execution (941568)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/28010");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/26789");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/26804");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/38721");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/38722");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2007/Dec/1019073.html");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2007/ms07-064");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could allow arbitrary code execution and can
  potentially compromise a user's system.");
  script_tag(name:"affected", value:"DirectX 7.0, 8.1 and 9.0 on Microsoft Windows 2000
  DirectX 9.0 on Microsoft Windows XP and 2003
  DirectX 10.0 on Microsoft Windows vista");
  script_tag(name:"insight", value:"The flaw is due to:

  - A boundary error in quartz.dll when parsing 'SAMI' files which can be
    exploited to cause a stack-based buffer overflow when opening a
    specially crafted file.

  - An error within the DirectShow technology when parsing 'AVI' and 'WAV'
    files.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS07-064.");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

# OS with Hotfix Check
if(hotfix_check_sp(win2k:5, xp:4, win2003:3, winVista:3) <= 0){
  exit(0);
}

directXver = registry_get_sz(key:"SOFTWARE\Microsoft\DirectX", item:"Version");
if(!egrep(pattern:"^4\.0[789]\..*", string:directXver)){
  exit(0);
}

# MS09-011 Hotfix check
if(hotfix_missing(name:"941568") == 0){
  exit(0);
}

dllFile = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(!dllFile){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllFile);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                     string:dllFile + "\quartz.dll");

dllVer = GetVer(file:file, share:share);
if(!dllVer){
  exit(0);
}

if(hotfix_check_sp(win2k:5) > 0)
{
  if(directXver =~ "^4\.07")
  {
    if(version_is_less(version:dllVer, test_version:"6.1.9.733")){
      report = report_fixed_ver(installed_version:dllVer, fixed_version:"6.1.9.733");
      security_message(port: 0, data: report);
    }
  }
  else if(directXver =~ "^4\.08")
  {
    if(version_is_less(version:dllVer, test_version:"6.3.1.890")){
      report = report_fixed_ver(installed_version:dllVer, fixed_version:"6.3.1.890");
      security_message(port: 0, data: report);
    }
  }
  else if(directXver =~ "^4\.09")
  {
    if(version_is_less(version:dllVer, test_version:"6.5.1.908")){
      report = report_fixed_ver(installed_version:dllVer, fixed_version:"6.5.1.908");
      security_message(port: 0, data: report);
    }
  }
  exit(0);
}

if(hotfix_check_sp(xp:4) > 0)
{
  if(directXver =~ "^4\.09")
  {
    SP = get_kb_item("SMB/WinXP/ServicePack");
    if("Service Pack 2" >< SP)
    {
      if(version_is_less(version:dllVer, test_version:"6.5.2600.3243")){
        report = report_fixed_ver(installed_version:dllVer, fixed_version:"6.5.2600.3243");
        security_message(port: 0, data: report);
      }
    }
  }
}

if(hotfix_check_sp(win2003:3) > 0)
{
  if(directXver =~ "^4\.09")
  {
    SP = get_kb_item("SMB/Win2003/ServicePack");
    if("Service Pack 1" >< SP)
    {
      if(version_is_less(version:dllVer, test_version:"6.5.3790.3035")){
        report = report_fixed_ver(installed_version:dllVer, fixed_version:"6.5.3790.3035");
        security_message(port: 0, data: report);
      }
    }
    else if("Service Pack 2" >< SP)
    {
      if(version_is_less(version:dllVer, test_version:"6.5.3790.4178")){
        report = report_fixed_ver(installed_version:dllVer, fixed_version:"6.5.3790.4178");
        security_message(port: 0, data: report);
      }
    }
  }
}

dllFile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                          item:"PathName");
if(!dllFile){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllFile);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                     string:dllFile + "\system32\quartz.dll");

dllVer = GetVer(file:file, share:share);
if(!dllVer){
  exit(0);
}

if(hotfix_check_sp(winVista:3) > 0)
{
  if(directXver =~ "^4\.09")
  {
    if(version_is_less(version:dllVer, test_version:"6.6.6000.16587")){
          report = report_fixed_ver(installed_version:dllVer, fixed_version:"6.6.6000.16587");
          security_message(port: 0, data: report);
    }
         exit(0);
  }
}

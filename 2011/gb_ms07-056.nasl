# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801713");
  script_version("2023-10-12T05:05:32+0000");
  script_tag(name:"last_modification", value:"2023-10-12 05:05:32 +0000 (Thu, 12 Oct 2023)");
  script_tag(name:"creation_date", value:"2011-01-14 07:39:17 +0100 (Fri, 14 Jan 2011)");
  script_cve_id("CVE-2007-3897");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Outlook Express And Windows Mail NNTP Protocol Heap Buffer Overflow Vulnerability (941202)");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2007/Oct/1018786.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/25908");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2007/Oct/1018785.html");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2007/ms07-056");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation leads to cause a heap-based buffer overflow by
  returning more data than requested by the client.");
  script_tag(name:"affected", value:"- Microsoft Windows XP Service Pack 2 and prior

  - Microsoft Windows 2000 Service Pack 4 and prior

  - Microsoft Windows 2K3 Service Pack 2 and prior

  - Microsoft Windows Vista");
  script_tag(name:"insight", value:"The flaw is due to a boundary error in 'inetcomm.dll' when processing
  NNTP (Network News Transfer Protocol) responses.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS07-056.");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2k:5, xp:3, win2003:3, winVista:3) <= 0){
  exit(0);
}

if(hotfix_missing(name:"941202") == 0){
  exit(0);
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(sysPath)
{
  sysVer = fetch_file_version(sysPath:sysPath, file_name:"Inetcomm.dll");
  if(sysVer)
  {
    if(hotfix_check_sp(win2k:5) > 0)
    {
      if(version_in_range(version:sysVer, test_version:"5.0", test_version2:"5.50.4980.1599") ||
         version_in_range(version:sysVer, test_version:"6.0", test_version2:"6.0.2800.1913")){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
      }
    }

    else if(hotfix_check_sp(xp:3) > 0)
    {
      SP = get_kb_item("SMB/WinXP/ServicePack");
      if("Service Pack 2" >< SP)
      {
         if(version_is_less(version:sysVer, test_version:"6.0.2900.3198")){
          security_message( port: 0, data: "The target host was found to be vulnerable" );
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
        if(version_is_less(version:sysVer, test_version:"6.0.3790.2992")){
          security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
         exit(0);
      }
      if("Service Pack 2" >< SP)
      {
        if(version_is_less(version:sysVer, test_version:"6.0.3790.4133")){
          security_message( port: 0, data: "The target host was found to be vulnerable" );
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

sysVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Inetcomm.dll");
if(!sysVer){
  exit(0);
}

if(hotfix_check_sp(winVista:3) > 0)
{
  if(version_is_less(version:sysVer, test_version:"6.0.6000.16545")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805015");
  script_version("2024-07-25T05:05:41+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2014-6332", "CVE-2014-6352");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-07-25 05:05:41 +0000 (Thu, 25 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-24 16:20:19 +0000 (Wed, 24 Jul 2024)");
  script_tag(name:"creation_date", value:"2014-11-12 10:12:10 +0530 (Wed, 12 Nov 2014)");
  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Microsoft Windows OLE Object Handling Code Execution Vulnerabilities (3011443)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS14-064.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A flaw exists due to unspecified errors
  when handling OLE objects within Microsoft Office files and Internet Explorer.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to execute arbitrary code and compromise a user's system.");

  script_tag(name:"affected", value:"- Microsoft Windows 8 x32/x64

  - Microsoft Windows Server 2012/R2

  - Microsoft Windows 8.1 x32/x64

  - Microsoft Windows 7 x32/x64 Service Pack 1 and prior

  - Microsoft Windows Vista x32/x64 Service Pack 2 and prior

  - Microsoft Windows 2003 x32/x64 Service Pack 2 and prior

  - Microsoft Windows Server 2008 R2 x64 Service Pack 1 and prior

  - Microsoft Windows Server 2008 x32/x64 Service Pack 2 and prior");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/kb/3011443");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70690");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70952");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/3010788");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/3006226");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/ms14-064");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2003:3, win2003x64:3, winVista:3, win7:2, win7x64:2, win2008:3,
                   win2008r2:2, win8:1, win8x64:1, win2012:1, win2012R2:1, win8_1:1,
                   win8_1x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllVer1 = fetch_file_version(sysPath:sysPath, file_name:"system32\Packager.dll");
dllVer2 = fetch_file_version(sysPath:sysPath, file_name:"system32\Oleaut32.dll");
if(!dllVer1 && !dllVer2){
  exit(0);
}


if(hotfix_check_sp(win2003x64:3,win2003:3) > 0 && dllVer1)
{
  if(version_is_less(version:dllVer1, test_version:"5.2.3790.5464")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

## Currently not supporting for Vista and Windows Server 2008 64 bit
if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(dllVer1)
  {
    if(version_is_less(version:dllVer1, test_version:"6.0.6002.19220")||
       version_in_range(version:dllVer1, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23526")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }

  if(dllVer2)
  {
    if(version_is_less(version:dllVer2, test_version:"6.0.6002.19216")||
       version_in_range(version:dllVer2, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23522")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
  exit(0);
}

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(dllVer1)
  {
    if(version_is_less(version:dllVer1, test_version:"6.1.7601.18645")||
       version_in_range(version:dllVer1, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22852")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
  if(dllVer2)
  {
    if(version_is_less(version:dllVer2, test_version:"6.1.7601.18640")||
       version_in_range(version:dllVer2, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22845")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
  exit(0);
}

if(hotfix_check_sp(win8:1, win8x64:1, win2012:1) > 0)
{
  if(dllVer1)
  {
    if(version_is_less(version:dllVer1, test_version:"6.2.9200.17160")||
       version_in_range(version:dllVer1, test_version:"6.2.9200.20000", test_version2:"6.2.9200.21277")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
  if(dllVer2)
  {
    if(version_is_less(version:dllVer2, test_version:"6.2.9200.17155")||
       version_in_range(version:dllVer2, test_version:"6.2.9200.20000", test_version2:"6.2.9200.21272")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
  exit(0);
}

## Win 8.1 and win2012R2
if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if((dllVer1 && version_is_less(version:dllVer1, test_version:"6.3.9600.17408")) ||
     (dllVer2 && version_is_less(version:dllVer2, test_version:"6.3.9600.17403"))){
   security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

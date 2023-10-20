# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805065");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2015-1643", "CVE-2015-1644");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-04-15 08:57:02 +0530 (Wed, 15 Apr 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Windows Privilege Elevation Vulnerabilities (3049576)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS15-038.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaws are due to:

  - A type confusion flaw related to NtCreateTransactionManager that may result
    in the operating system failing to properly validate and enforce impersonation
    levels.

  - The operating system failing to properly validate and enforce impersonation
    levels when handling an MS-DOS device name. This may allow a local attacker
    to gain elevated privileges.");

  script_tag(name:"impact", value:"Successful exploitation will allow local users
  to gain privileges via a crafted application.");

  script_tag(name:"affected", value:"- Microsoft Windows 8 x32/x64

  - Microsoft Windows Server 2012/R2

  - Microsoft Windows 8.1 x32/x64

  - Microsoft Windows 2003 x32/x64 Service Pack 2 and prior

  - Microsoft Windows Vista x32/x64 Service Pack 2 and prior

  - Microsoft Windows Server 2008 x32/x64 Service Pack 2 and prior

  - Microsoft Windows 7 x32/x64 Service Pack 1 and prior

  - Microsoft Windows Server 2008 R2 x64 Service Pack 1 and prior");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/3045685");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/3045999");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS15-038");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
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

if(hotfix_check_sp(win2003:3, win2003x64:3, winVista:3, win7:2, win7x64:2,
                   win2008r2:2, win8:1, win8x64:1, win2012:1,win2012R2:1,
                   win8_1:1, win8_1x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"System32\Clfsw32.dll");
exeVer = fetch_file_version(sysPath:sysPath, file_name:"System32\Ntoskrnl.exe");
if( ! dllVer && ! exeVer ) exit( 0 );

## Avoid passing FALSE values to the version_* functions later if fetch_file_version() returns FALSE
if( ! dllVer ) dllVer = "unknown";
if( ! exeVer ) exeVer = "unknown";

if(hotfix_check_sp(win2003x64:3,win2003:3) > 0)
{
  if(version_is_less(version:dllVer, test_version:"5.2.3790.5562") ||
     version_is_less(version:exeVer, test_version:"5.2.3790.5583"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

## Currently not supporting for Vista and Windows Server 2008 64 bit
if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.0.6002.19331") ||
     version_in_range(version:dllVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23638") ||
     version_is_less(version:exeVer, test_version:"6.0.6002.19346") ||
     version_in_range(version:exeVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23653"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.1.7601.18777") ||
     version_in_range(version:dllVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22980") ||
     version_is_less(version:exeVer, test_version:"6.1.7601.18798") ||
     version_in_range(version:exeVer, test_version:"6.1.7601.22000", test_version2:"6.0.6002.23001"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

if(hotfix_check_sp(win8:1, win8x64:1, win2012:1) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.2.9200.17291") ||
     version_in_range(version:dllVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.21407") ||
     version_is_less(version:exeVer, test_version:"6.2.9200.17313") ||
     version_in_range(version:exeVer, test_version:"6.2.9200.20000", test_version2:"6.0.6002.21427"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

## Win 8.1 and win2012R2
if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.3.9600.17719") ||
     version_is_less(version:exeVer, test_version:"6.3.9600.17736"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

exit(99);

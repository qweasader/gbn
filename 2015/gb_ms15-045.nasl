# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only
if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802091");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2015-1675", "CVE-2015-1695", "CVE-2015-1696",
                "CVE-2015-1697", "CVE-2015-1698", "CVE-2015-1699");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-05-13 13:29:45 +0530 (Wed, 13 May 2015)");
  script_name("Microsoft Windows Journal Remote Code Execution Vulnerability (3046002)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS15-045.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an unspecified error
  within Windows Journal when handling Journal (JNT) files.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code and compromise a user's system.");

  script_tag(name:"affected", value:"- Microsoft Windows 8/8.1 x32/x64

  - Microsoft Windows Server 2012/R2

  - Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior

  - Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior

  - Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior

  - Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS15-045");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/library/dd759248.aspx");

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

if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, win2008:3, win2008r2:2, win8:1,
                   win2012:1, win2012R2:1, win8_1:1, win8_1x64:1) <= 0){
  exit(0);
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                           item:"CommonFilesDir");
if(!sysPath){
  exit(0);
}

sysPath = sysPath + "\Microsoft Shared\ink";

Win32sysVer = fetch_file_version(sysPath:sysPath, file_name:"Journal.dll");
if(!Win32sysVer){
  exit(0);
}

## Currently not supporting for Vista and Windows Server 2008 64 bit
if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(version_is_less(version:Win32sysVer, test_version:"6.0.6002.19356") ||
     version_in_range(version:Win32sysVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.23663")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_is_less(version:Win32sysVer, test_version:"6.1.7601.18815") ||
     version_in_range(version:Win32sysVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.23019")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win8:1, win2012:1) > 0)
{
  if(version_is_less(version:Win32sysVer, test_version:"6.2.9200.17330") ||
     version_in_range(version:Win32sysVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.21443")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

## Win 8.1 Windows Server 2012 R2
else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_is_less(version:Win32sysVer, test_version:"6.3.9600.17793")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

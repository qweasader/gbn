# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802073");
  script_version("2023-07-27T05:05:08+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2014-1812");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-05-14 12:36:12 +0530 (Wed, 14 May 2014)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("Microsoft Group Policy Preferences Privilege Elevation Vulnerability (2962486)");

  script_tag(name:"summary", value:"This host is missing an important security update according to Microsoft
  Bulletin MS14-025.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw is due the way Active Directory distributes passwords that are configured
  using Group Policy preferences.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker could decrypt the passwords and
  use them to elevate privileges on the domain.");

  script_tag(name:"affected", value:"- Microsoft Windows 8 x32/x64

  - Microsoft Windows 8.1 x32/x64

  - Microsoft Windows Server 2012

  - Microsoft Windows Server 2012 R2

  - Microsoft Windows 7 x32/x64 Service Pack 1 and prior

  - Microsoft Windows Vista x32/x64 Service Pack 2 and prior

  - Microsoft Windows Server 2008 R2 x64 Service Pack 1 and prior

  - Microsoft Windows Server 2008 x32/x64 Service Pack 2 and prior");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2928120");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67275");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2961899");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/ms14-025");
  script_category(ACT_GATHER_INFO);
  script_family("Windows : Microsoft Bulletins");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(winVista:3, winVistax64:3, win7:2, win7x64:2, win2008:3,
                   win2008x64:3, win2008r2:2, win8:1, win8x64:1, win2012:1,
                   win8_1:1, win8_1x64:1) <= 0)
{
  exit(0);
}

## Client systems are only affected if Remote Server Administration Tools
## has been installed.

## Server systems are only affected if Group Policy Management is configured.
## on the server.
gpmc_key1 = "SOFTWARE\Microsoft\Group Policy Management Console";
if(!registry_key_exists(key:gpmc_key1)){
  exit(0);
}

gpmc_key2 = "SOFTWARE\Classes\AppID\gppref.dll";
if(!registry_key_exists(key:gpmc_key2)){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

sysVer = fetch_file_version(sysPath:sysPath, file_name:"\system32\Gppref.dll");
if(!sysVer){
  exit(0);
}

## Currently not supporting for Vista 64 bit
if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(version_is_less(version:sysVer, test_version:"6.0.6002.19047") ||
     version_in_range(version:sysVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23338")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_is_less(version:sysVer, test_version:"6.1.7601.18399") ||
     version_in_range(version:sysVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22604")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win8:1, win8x64:1, win2012:1) > 0)
{
  if(version_is_less(version:sysVer, test_version:"6.2.9200.16859") ||
     version_in_range(version:sysVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.20977")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

## Currently not supporting for Windows Server 2012 R2
else if(hotfix_check_sp(win8_1:1, win8_1x64:1) > 0)
{
  if(version_in_range(version:sysVer, test_version:"6.3.9600.16000", test_version2:"6.3.9600.16659") ||
     version_in_range(version:sysVer, test_version:"6.3.9600.17000", test_version2:"6.3.9600.17040")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

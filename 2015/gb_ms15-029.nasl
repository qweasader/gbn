# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805501");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2015-0076");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-03-11 13:26:55 +0530 (Wed, 11 Mar 2015)");
  script_name("Microsoft Windows Photo Decoder Information Disclosure Vulnerability (3035126)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS15-029.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw exists due to error in the Photo
  decoder that is triggered as the program fails to handle uninitialized
  memory when parsing a specially crafted JPEG XR image");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to potentially sensitive information in memory.");

  script_tag(name:"affected", value:"- Microsoft Windows 8 x32/x64

  - Microsoft Windows 8.1 x32/x64

  - Microsoft Windows Server 2012/R2

  - Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior

  - Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior

  - Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior

  - Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/3035126");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS15-029");

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

if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, win2008:3, win2008r2:2,
                   win8:1, win8x64:1, win2012:1, win2012R2:1, win8_1:1,
                   win8_1x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Wmphoto.dll");
if(!dllVer){
  exit(0);
}

## Currently not supporting for Vista and Windows Server 2008 64 bit
if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(version_is_less(version:dllVer, test_version:"7.0.6002.19299") ||
     version_in_range(version:dllVer, test_version:"7.0.6002.23000", test_version2:"7.0.6002.23608")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.1.7601.18742") ||
     version_in_range(version:dllVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22948") ||
     version_in_range(version:dllVer, test_version:"6.2.9200.17000", test_version2:"6.2.9200.17253") ||
     version_in_range(version:dllVer, test_version:"6.2.9200.21000", test_version2:"6.2.9200.21370")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

if(hotfix_check_sp(win8:1, win8x64:1, win2012:1) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.2.9200.17247") ||
     version_in_range(version:dllVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.21363")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

## Win 8.1 and win2012R2
if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.3.9600.17668")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

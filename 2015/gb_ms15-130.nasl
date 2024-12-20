# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806172");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2015-6130");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-12-09 09:39:22 +0530 (Wed, 09 Dec 2015)");
  script_name("Microsoft Windows Uniscribe Remote Code Execution Vulnerability (3108670)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS15-130.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists when Windows Uniscribe
  improperly parses specially crafted fonts.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code in the context of the vulnerable application. Failed
  exploit attempts will result in a denial-of-service condition.");

  script_tag(name:"affected", value:"- Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior

  - Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS15-130");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/78500");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3108670#bookmark-fileinfo");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Usp10.dll");
if(dllVer)
{
  if (dllVer =~ "^(1\.626\.7601\.1)"){
    Vulnerable_range = "1.626.7601.18000 - 1.626.7601.19053";
   }
  else if (dllVer =~ "^(1\.626\.7601\.2)"){
    Vulnerable_range = "1.626.7601.22000 - 1.626.7601.23258";
  }
}

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_in_range(version:dllVer, test_version:"1.626.7601.18000", test_version2:"1.626.7601.19053")||
     version_in_range(version:dllVer, test_version:"1.626.7601.22000", test_version2:"1.626.7601.23258"))
  {
    report = 'File checked:     ' + sysPath + "\system32\Usp10.dll" + '\n' +
             'File version:     ' + dllVer  + '\n' +
             'Vulnerable range: ' + Vulnerable_range + '\n' ;
    security_message(data:report);
    exit(0);
  }
}

exit(99);
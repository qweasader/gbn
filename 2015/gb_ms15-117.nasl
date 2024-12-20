# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806615");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2015-6098");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-11-11 12:47:24 +0530 (Wed, 11 Nov 2015)");
  script_name("Microsoft Windows NDIS Elevation of Privilege Vulnerability (3101722)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS15-117.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The error exists as NDIS fails to check the
  length of a buffer prior to copying memory into it.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to gain elevated privileges on a targeted system.");

  script_tag(name:"affected", value:"- Microsoft Windows Vista x32/x64 Edition Service Pack 2

  - Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2

  - Microsoft Windows 7 x32/x64 Edition Service Pack 1

  - Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3101722");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS15-117");

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

if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, win2008:3, win2008r2:2) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"System32\drivers\Ndis.sys");
if(!dllVer){
  exit(0);
}

## Currently not supporting for Vista and Windows Server 2008 64 bit
if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.0.6002.19512"))
  {
     Vulnerable_range = "Less than 6.0.6002.19512";
     VULN = TRUE ;
  }
  else if(version_in_range(version:dllVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23821"))
  {
    Vulnerable_range = "6.0.6002.23000 - 6.0.6002.23821";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.1.7601.19030")){
   Vulnerable_range = "Less than 6.1.7601.19030";
   VULN = TRUE ;
  }
  else if(version_in_range(version:dllVer, test_version:"6.1.7601.23000", test_version2:"6.1.7601.23234")){
   Vulnerable_range = "6.1.7601.23000 - 6.1.7601.23234";
   VULN = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "\system32\Drivers\Ndis.sys" + '\n' +
           'File version:     ' + dllVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}

# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809307");
  script_version("2023-07-21T05:05:22+0000");
  script_cve_id("CVE-2016-3348", "CVE-2016-3349", "CVE-2016-3354", "CVE-2016-3355",
                "CVE-2016-3356");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-12 22:12:00 +0000 (Fri, 12 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-09-14 07:48:12 +0530 (Wed, 14 Sep 2016)");
  script_name("Microsoft Graphics Component Multiple Vulnerabilities (3185848)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-106.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - The way that certain Windows kernel-mode drivers handle objects in memory.

  - The way that the Windows Graphics Device Interface handles objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to run arbitrary code in kernel mode, to retrieve information from a targeted
  system, also could take control of the affected system.");

  script_tag(name:"affected", value:"- Microsoft Windows 8.1 x32/x64

  - Microsoft Windows 10 x32/x64

  - Microsoft Windows Server 2012/2012R2

  - Microsoft Windows 10 Version 1511 x32/x64

  - Microsoft Windows Vista x32/x64 Service Pack 2

  - Microsoft Windows Server 2008 x32/x64 Service Pack 2

  - Microsoft Windows 7 x32/x64 Service Pack 1

  - Microsoft Windows Server 2008 R2 x64 Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3185911");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92782");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92783");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92784");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92787");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-106");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
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

if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, win2008:3, win2008r2:2, winVistax64:3,
                   win2008x64:3, win2012:1, win2012R2:1, win8_1:1, win8_1x64:1, win10:1,
                   win10x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

win32kVer = fetch_file_version(sysPath:sysPath, file_name:"System32\Win32k.sys");

if(!win32kVer){
  exit(0);
}

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
    ## Presently GDR information is not available.
    if(version_is_less(version:win32kVer, test_version:"6.1.7601.23528"))
    {
      Vulnerable_range = "Less than 6.1.7601.23528";
      VULN = TRUE ;
    }
}

else if(hotfix_check_sp(winVista:3, winVistax64:3, win2008:3, win2008x64:3) > 0)
{
    if(version_is_less(version:win32kVer, test_version:"6.0.6002.19681"))
    {
      Vulnerable_range = "Less than 6.0.6002.19681";
      VULN = TRUE ;
    }

    else if(version_in_range(version:win32kVer, test_version:"6.0.6002.24000", test_version2:"6.0.6002.24007"))
    {
      Vulnerable_range = "6.0.6002.24000 - 6.0.6002.24007";
      VULN = TRUE ;
    }
}

else if(hotfix_check_sp(win2012:1) > 0)
{
  if(version_is_less(version:win32kVer, test_version:"6.2.9200.21966"))
  {
     Vulnerable_range = "Less than 6.2.9200.21966";
     VULN = TRUE ;
  }
}

## Win 8.1 and win2012R2
else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_is_less(version:win32kVer, test_version:"6.3.9600.18439"))
  {
    Vulnerable_range = "Less than 6.3.9600.18439";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win10:1, win10x64:1) > 0)
{
  if(version_is_less(version:win32kVer, test_version:"10.0.10240.16384") )
  {
    Vulnerable_range = "Less than 10.0.10240.16384";
    VULN = TRUE;
  }

  else if(version_in_range(version:win32kVer, test_version:"10.0.10586.0", test_version2:"10.0.10586.19"))
  {
    Vulnerable_range = "10.0.10586.0 - 10.0.10586.19";
    VULN = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "\System32\Win32k.sys" + '\n' +
           'File version:     ' + win32kVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);

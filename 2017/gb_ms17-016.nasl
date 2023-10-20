# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810815");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2017-0055");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-12 01:29:00 +0000 (Wed, 12 Jul 2017)");
  script_tag(name:"creation_date", value:"2017-03-15 12:27:08 +0530 (Wed, 15 Mar 2017)");
  script_name("Microsoft Windows IIS Privilege Escalation Vulnerability (4013074)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS17-016");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to Microsoft IIS Server
  fails to properly sanitize a specially crafted request.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to perform cross-site scripting attacks on affected systems and run
  script in the security context of the current user. These attacks could allow
  the attacker to read content that the attacker is not authorized to read, use
  the victim's identity to take actions on behalf of the victim, and inject
  malicious content in the victim's browser.");

  script_tag(name:"affected", value:"- Microsoft Windows 8.1 x32/x64

  - Microsoft Windows 10 x32/x64

  - Microsoft Windows Server 2012/2012R2

  - Microsoft Windows 10 Version 1511 x32/x64

  - Microsoft Windows 10 Version 1607 x32/x64

  - Microsoft Windows Vista x32/x64 Edition Service Pack 2

  - Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2

  - Microsoft Windows 7 x32/x64 Edition Service Pack 1

  - Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1

  - Microsoft Windows Server 2016");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/4013074");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96622");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/library/security/MS17-016");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS17-016");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, win2008:3, win2008r2:2, winVistax64:3,
                   win2008x64:3, win2012:1, win2012R2:1, win8_1:1, win8_1x64:1, win10:1,
                   win10x64:1, win2016:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

winVer = fetch_file_version(sysPath:sysPath, file_name:"System32\Win32k.sys");
advVer = fetch_file_version(sysPath:sysPath, file_name:"System32\advapi32.dll");
if(!winVer && !advVer){
  exit(0);
}

## Extracted patch and checked for version
if(hotfix_check_sp(winVista:3, winVistax64:3, win2008:3, win2008x64:3) > 0 && advVer)
{
    if(version_is_less(version:advVer, test_version:"6.0.6002.19680"))
    {
      Vulnerable_range1 = "Less than 6.0.6002.19680";
      VULN1 = TRUE ;
    }

    else if(version_in_range(version:advVer, test_version:"6.0.6002.24000", test_version2:"6.0.6002.24064"))
    {
      Vulnerable_range1 = "6.0.6002.24000 - 6.0.6002.24064";
      VULN1 = TRUE ;
    }
}

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
    ## Presently GDR information is not available.
    if(version_is_less(version:winVer, test_version:"6.1.7601.23677"))
    {
      Vulnerable_range = "Less than 6.1.7601.23677";
      VULN = TRUE ;
    }
}

## Win 8.1 and win2012R2
else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_is_less(version:winVer, test_version:"6.3.9600.18603"))
  {
    Vulnerable_range = "Less than 6.3.9600.18603";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win2012:1) > 0)
{
  if(version_is_less(version:winVer, test_version:"6.2.9200.22097"))
  {
     Vulnerable_range = "Less than 6.2.9200.22097";
     VULN = TRUE;
  }
}


else if(hotfix_check_sp(win10:1, win10x64:1, win2016:1) > 0)
{
  if(version_is_less(version:winVer, test_version:"10.0.10240.16384"))
  {
    Vulnerable_range = "Less than 10.0.10240.16384";
    VULN = TRUE;
  }

  else if(winVer && version_in_range(version:winVer, test_version:"10.0.10586.0", test_version2:"10.0.10586.19"))
  {
    Vulnerable_range = "10.0.10586.0 - 10.0.10586.19";
    VULN = TRUE;
  }

  else if( winVer && version_in_range(version:winVer, test_version:"10.0.14393.0", test_version2:"10.0.14393.593"))
  {
    Vulnerable_range = "10.0.14393.0 - 10.0.14393.593";
    VULN = TRUE;
  }
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "\System32\Win32k.sys" + '\n' +
           'File version:     ' + winVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}

else if(VULN1)
{
  report = 'File checked:     ' + sysPath + "\System32\advapi32.dll" + '\n' +
           'File version:     ' + advVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range1 + '\n' ;
  security_message(data:report);
  exit(0);
}

exit(0);

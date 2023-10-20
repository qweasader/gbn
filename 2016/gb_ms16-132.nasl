# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809466");
  script_version("2023-07-20T05:05:17+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2016-7210", "CVE-2016-7205", "CVE-2016-7217", "CVE-2016-7256");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-12 22:14:00 +0000 (Fri, 12 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-11-09 09:56:10 +0530 (Wed, 09 Nov 2016)");
  script_name("Microsoft Graphics Component Multiple Vulnerabilities (3199120)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-132.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - the ATMFD component improperly discloses the contents of its memory.

  - the Windows Animation Manager improperly handles objects in memory.

  - the Windows font library improperly handles specially crafted embedded fonts.

  - the Windows Media Foundation improperly handles objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to install programs, view, change, or delete data, or create new accounts with
  full user rights, and to obtain information to further compromise the user's
  system.");

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
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3199120");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94030");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94033");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94066");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94156");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-132");

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

if(hotfix_check_sp(winVista:3, winVistax64:3, win7:2, win7x64:2, win2008:3, win2008x64:3,
                   win2008r2:2, win2012:1, win2012R2:1, win8_1:1, win8_1x64:1,
                   win10:1, win10x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

dllver = fetch_file_version(sysPath:sysPath, file_name:"fontsub.dll");
edgeVer = fetch_file_version(sysPath:sysPath, file_name:"edgehtml.dll");
if(!dllver && !edgeVer){
  exit(0);
}

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0 && dllver)
{
  if(version_is_less(version:dllver, test_version:"6.1.7601.23587"))
  {
    Vulnerable_range = "Less than 6.1.7601.23587";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(winVista:3, win2008:3) > 0 && dllver)
{
  if(version_is_less(version:dllver, test_version:"6.0.6002.18272"))
  {
    Vulnerable_range = "Less than 6.0.6002.18272";
    VULN = TRUE ;
  }
  else if(version_in_range(version:dllver, test_version:"6.0.6002.23000", test_version2:"6.0.6002.24031"))
  {
    Vulnerable_range = "6.0.6002.23000 - 6.0.6002.24031";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0 && dllver)
{
  if(version_is_less(version:dllver, test_version:"6.3.9600.17415"))
  {
    Vulnerable_range = "Less than 6.3.9600.17415";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win2012:1) > 0 && dllver)
{
  if(version_is_less(version:dllver, test_version:"6.2.9200.16384"))
  {
    Vulnerable_range = "Less than 6.2.9200.16384";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win10:1, win10x64:1) > 0 && edgeVer)
{
  if(version_is_less(version:edgeVer, test_version:"11.0.10240.17184"))
  {
    Vulnerable_range2 = "Less than 11.0.10240.17184";
    VULN2 = TRUE ;
  }
  else if(version_in_range(version:edgeVer, test_version:"11.0.10586.0", test_version2:"11.0.10586.671"))
  {
    Vulnerable_range2 = "11.0.10586.0 - 11.0.10586.671";
    VULN2 = TRUE ;
  }

  else if(version_in_range(version:edgeVer, test_version:"11.0.14393.0", test_version2:"11.0.14393.446"))
  {
    Vulnerable_range2 = "11.0.14393.0 - 11.0.14393.446";
    VULN2 = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "\fontsub.dll" + '\n' +
           'File version:     ' + dllver  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}

if(VULN2)
{
  report = 'File checked:     ' + sysPath + "\edgehtml.dll" + '\n' +
           'File version:     ' + edgeVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range2 + '\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);

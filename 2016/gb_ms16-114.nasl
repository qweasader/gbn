# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809225");
  script_version("2024-06-21T05:05:42+0000");
  script_cve_id("CVE-2016-3345");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-06-21 05:05:42 +0000 (Fri, 21 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-12 22:12:00 +0000 (Fri, 12 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-09-14 10:24:16 +0530 (Wed, 14 Sep 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft SMBv1 Server Authenticated Remote Code Execution Vulnerability (3185879)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-114.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An authenticated remote code execution
  vulnerability exists in Windows that is caused when Server Message Block
  (SMB) improperly handles certain logging activities, resulting in memory
  corruption.");

  script_tag(name:"impact", value:"Successful exploitation will allow  attacker
  to take complete control of an affected system. An attacker could then install,
  programs, view, change, or delete data  or create new accounts with full user
  rights.");

  script_tag(name:"affected", value:"- Microsoft Windows Vista x32/x64 Service Pack 2

  - Microsoft Windows Server 2008 x32/x64 Service Pack 2

  - Microsoft Windows 7 x32/x64 Service Pack 1

  - Microsoft Windows Server 2008 R2 x64 Service Pack 1

  - Microsoft Windows 8.1 x32/x64

  - Microsoft Windows Server 2012/2012R2

  - Microsoft Windows 10 x32/x64

  - Microsoft Windows 10 Version 1511 x32/x64");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3185879");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92859");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-114");
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

if(hotfix_check_sp(winVista:3, winVistax64:3, win2008x64:3, win7:2, win7x64:2, win2008:3, win2008r2:2,
                   win2012:1,  win2012R2:1, win8_1:1, win8_1x64:1, win10:1, win10x64:1) <= 0){
  exit(0);
}

smbPath = smb_get_systemroot();
if(!smbPath ){
  exit(0);
}

smbVer = fetch_file_version(sysPath: smbPath, file_name:"System32\drivers\Srv.sys");
if(!smbVer){
  exit(0);
}

if(hotfix_check_sp(winVista:3, win2008:3, winVistax64:3, win2008x64:3) > 0)
{
  if(version_is_less(version:smbVer, test_version:"6.0.6002.19673"))
  {
    Vulnerable_range = "Less than 6.0.6002.19673";
    VULN = TRUE ;
  }
  else if(version_in_range(version:smbVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23999"))
  {
    Vulnerable_range = "6.0.6002.23000 - 6.0.6002.23999";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win2012:1) > 0)
{
  if(version_is_less(version:smbVer, test_version:"6.2.9200.21954"))
  {
    Vulnerable_range = "Less than 6.2.9200.21954";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_is_less(version:smbVer, test_version:"6.3.9600.18432"))
  {
     Vulnerable_range = "Less than 6.3.9600.18432";
     VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_is_less(version:smbVer, test_version:"6.1.7601.23517"))
  {
     Vulnerable_range = "Less than 6.1.7601.23517";
     VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win10:1, win10x64:1) > 0)
{
  if(version_in_range(version:smbVer, test_version:"10.0.10586.000", test_version2:"10.0.10586.588"))
  {
    Vulnerable_range = "10.0.10586.000 - 10.0.10586.588";
    VULN = TRUE ;
  }

  else if(version_is_less(version:smbVer, test_version:"10.0.10240.17113"))
  {
    Vulnerable_range = "Less than 10.0.10240.17113";
    VULN = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + smbPath + "\System32\drivers\Srv.sys" + '\n' +
           'File version:     ' + smbVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}

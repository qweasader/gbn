# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807385");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2016-7223", "CVE-2016-7224", "CVE-2016-7225", "CVE-2016-7226");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-12 22:14:00 +0000 (Fri, 12 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-11-09 12:02:33 +0530 (Wed, 09 Nov 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Virtual Hard Disk Driver Multiple Vulnerabilities (3199647)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-138.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist when the Windows
  Virtual Hard Disk Driver fails to properly handle user access to certain
  files. An attacker who successfully exploited the vulnerabilities could
  manipulate files in locations not intended to be available to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to execute a specially crafted application on the system.");

  script_tag(name:"affected", value:"- Microsoft Windows 8.1 x32/x64

  - Microsoft Windows Server 2012/2012R2

  - Microsoft Windows 10 x32/x64

  - Microsoft Windows 10 Version 1511 x32/x64

  - Microsoft Windows 10 Version 1607 x32/x64");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3199647");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94003");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94017");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94016");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94018");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3197873");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3197874");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3197876");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3197877");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/library/security/MS16-138");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-138");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2012:1, win2012R2:1, win8_1:1, win8_1x64:1, win10:1, win10x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

MsvVer = fetch_file_version(sysPath:sysPath, file_name:"System32\Msvidctl.dll");
if(!MsvVer){
  exit(0);
}

if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_is_less(version:MsvVer, test_version:"6.5.9600.18512"))
  {
    Vulnerable_range = "Less than 6.5.9600.18512";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win2012:1) > 0)
{
  if(version_is_less(version:MsvVer, test_version:"6.5.9200.22006"))
  {
    Vulnerable_range = "Less than 6.5.9200.22006";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win10:1, win10x64:1) > 0)
{
  if(version_is_less(version:MsvVer, test_version:"6.5.10240.17184"))
  {
    Vulnerable_range = "Less than 6.5.10240.17184";
    VULN = TRUE ;
  }

  else if(version_in_range(version:MsvVer, test_version:"6.5.10586.0", test_version2:"6.5.10586.671"))
  {
    Vulnerable_range = "6.5.10586.0 - 6.5.10586.671";
    VULN = TRUE ;
  }

  else if(version_in_range(version:MsvVer, test_version:"6.5.14393.0", test_version2:"6.5.14393.446"))
  {
    Vulnerable_range = "6.5.14393.0 - 6.5.14393.446";
    VULN = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "\System32\Msvidctl.dll" + '\n' +
           'File version:     ' + MsvVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);

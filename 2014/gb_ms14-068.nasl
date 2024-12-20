# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804799");
  script_version("2024-07-17T05:05:38+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2014-6324");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-07-17 05:05:38 +0000 (Wed, 17 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 17:48:24 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2014-11-19 12:57:43 +0530 (Wed, 19 Nov 2014)");
  script_name("Microsoft Windows Kerberos Checksum Remote Privilege Escalation Vulnerability (3011780)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS14-068.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Vulnerability exists when Microsoft Kerberos
  KDC implementations fail to properly validate signatures.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to escalate the privileges.");

  script_tag(name:"affected", value:"- Microsoft Windows 8 x32/x64

  - Microsoft Windows Server 2012/R2

  - Microsoft Windows 8.1 x32/x64

  - Microsoft Windows 7 x32/x64 Service Pack 1 and prior

  - Microsoft Windows Vista x32/x64 Service Pack 2 and prior

  - Microsoft Windows 2003 x32/x64 Service Pack 2 and prior

  - Microsoft Windows Server 2008 R2 x64 Service Pack 1 and prior

  - Microsoft Windows Server 2008 x32/x64 Service Pack 2 and prior");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/213119");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70958");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/3011780");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2014/ms14-068");
  script_xref(name:"URL", value:"http://blogs.technet.com/b/srd/archive/2014/11/18/additional-information-about-cve-2014-6324.aspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
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

if(hotfix_check_sp(win2003:3, win2003x64:3, winVista:3, winVistax64:3, win7:2,
                   win7x64:2, win2008:3, win2008x64:3, win2008r2:2, win8:1,
                   win8x64:1, win2012:1, win2012R2:1, win8_1:1, win8_1x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"Kerberos.dll");
if(!dllVer){
  exit(0);
}

if(hotfix_check_sp(win2003:3, win2003x64:3) > 0)
{
  if(version_is_less(version:dllVer, test_version:"5.2.3790.5467"))
  {
    VULN = TRUE;
    Vulnerable_range = "Less than 5.2.3790.5467";
  }
}

else if(hotfix_check_sp(winVista:3, winVistax64:3, win2008:3, win2008x64:3) > 0)
{
  if(version_in_range(version:dllVer, test_version:"6.0.6002.18000", test_version2:"6.0.6002.19219"))
  {
    VULN = TRUE;
    Vulnerable_range = "6.0.6002.18000 - 6.0.6002.19219";
  }
  else if(version_in_range(version:dllVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23526"))
  {
    VULN = TRUE;
    Vulnerable_range = "6.0.6002.23000 - 6.0.6002.23526";
  }
}

else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_in_range(version:dllVer, test_version:"6.1.7601.18000", test_version2:"6.1.7601.18657"))
  {
    VULN = TRUE;
    Vulnerable_range = "6.1.7601.18000 - 6.1.7601.18657";

  }
  else if(version_in_range(version:dllVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22864"))
  {
    VULN = TRUE;
    Vulnerable_range = "6.1.7601.22000 - 6.1.7601.22864";
  }
}

else if(hotfix_check_sp(win8:1, win2012:1) > 0)
{
  if(version_in_range(version:dllVer, test_version:"6.2.9200.16000", test_version2:"6.2.9200.17171"))
  {
    VULN = TRUE;
    Vulnerable_range = "6.2.9200.16000 - 6.2.9200.17171";
  }
  else if(version_in_range(version:dllVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.21288"))
  {
    VULN = TRUE;
    Vulnerable_range = "6.2.9200.20000 - 6.2.9200.21288";
  }
}

else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.3.9600.17423"))
  {
    VULN = TRUE;
    Vulnerable_range = "Less than 6.3.9600.17423";
  }
}

if(VULN)
{
  report = 'File checked:     ' + "\Kerberos.dll" + '\n' +
           'File version:     ' + dllVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);

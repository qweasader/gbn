# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808018");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2016-0171", "CVE-2016-0173", "CVE-2016-0174", "CVE-2016-0196",
                "CVE-2016-0175", "CVE-2016-0176", "CVE-2016-0197");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-12 22:11:00 +0000 (Fri, 12 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-05-11 09:35:43 +0530 (Wed, 11 May 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Kernel-Mode Drivers Privilege Elevation Vulnerabilities (3158222)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-062.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - When the Windows kernel-mode driver fails to properly handle objects in
    memory and incorrectly maps kernel memory

  - When the DirectX Graphics kernel subsystem (dxgkrnl.sys) improperly handles
    objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to run arbitrary code in kernel mode, and to take control over the
  affected system, also could retrieve the memory address of a kernel object.");

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

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3158222");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/library/security/MS16-062");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-062");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, win2008:3, win2008r2:2,
                   win2012:1, win2012R2:1, win8_1:1, win8_1x64:1,win10:1, win10x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllVer1 = fetch_file_version(sysPath:sysPath, file_name:"System32\Win32k.sys");
dllVer2 = fetch_file_version(sysPath:sysPath, file_name:"System32\Dxgkrnl.sys");

if(!dllVer1 && !dllVer2){
  exit(0);
}

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(dllVer1)
  {
    if(version_is_less(version:dllVer1, test_version:"6.1.7601.23418"))
    {
      Vulnerable_range1 = "Less than 6.1.7601.23418";
      VULN1 = TRUE ;
    }
  }
  else if(dllVer2)
  {
    if(version_is_less(version:dllVer2, test_version:"6.1.7601.23418"))
    {
      Vulnerable_range2 = "Less than 6.1.7601.23418";
      VULN2 = TRUE ;
    }
  }
}

else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(dllVer1)
  {
    if(version_is_less(version:dllVer1, test_version:"6.0.6002.19636"))
    {
      Vulnerable_range1 = "Less than 6.0.6002.19636";
      VULN1 = TRUE ;
    }
    else if(version_in_range(version:dllVer1, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23949"))
    {
      Vulnerable_range1 = "6.0.6002.23000 - 6.0.6002.23949";
      VULN1 = TRUE ;
    }
  }
  else if(dllVer2)
  {
    if(version_is_less(version:dllVer2, test_version:"6.0.6002.19636"))
    {
      Vulnerable_range2 = "Less than 6.0.6002.19636";
      VULN2 = TRUE ;
    }
    else if(version_in_range(version:dllVer2, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23949"))
    {
      Vulnerable_range2 = "6.0.6002.23000 - 6.0.6002.23949";
      VULN2 = TRUE ;
    }
  }
}

else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(dllVer1)
  {
    if(version_is_less(version:dllVer1, test_version:"6.3.9600.18302"))
    {
      Vulnerable_range1 = "Less than 6.3.9600.18302";
      VULN1 = TRUE ;
    }
  }
  else if(dllVer2)
  {
    if(version_is_less(version:dllVer2, test_version:"6.3.9600.18302"))
    {
      Vulnerable_range2 = "Less than 6.3.9600.18302";
      VULN2 = TRUE ;
    }
  }
}

else if(hotfix_check_sp(win2012:1) > 0)
{
  if(dllVer1)
  {
    if(version_is_less(version:dllVer1, test_version:"6.2.9200.21833"))
    {
      Vulnerable_range1 = "Less than 6.2.9200.21833";
      VULN1 = TRUE ;
    }
  }
  else if(dllVer2)
  {
    if(version_is_less(version:dllVer2, test_version:"6.2.9200.21831"))
    {
      Vulnerable_range2 = "Less than 6.2.9200.21831";
      VULN2 = TRUE ;
    }
  }
}

else if(hotfix_check_sp(win10:1, win10x64:1) > 0)
{
  if(dllVer1)
  {
    if(version_is_less(version:dllVer1, test_version:"10.0.10240.16384"))
    {
      Vulnerable_range1 = "Less than 10.0.10240.16384";
      VULN1 = TRUE ;
    }
    else if(version_in_range(version:dllVer1, test_version:"10.0.10586.0", test_version2:"10.0.10586.19"))
    {
      Vulnerable_range1 = "10.0.10586.0 - 10.0.10586.19";
      VULN1 = TRUE ;
    }
  }
  else if(dllVer2)
  {
    if(version_is_less(version:dllVer2, test_version:"10.0.10240.16841"))
    {
      Vulnerable_range2 = "Less than 10.0.10240.16841";
      VULN2 = TRUE ;
    }
    else if(version_in_range(version:dllVer2, test_version:"10.0.10586.0", test_version2:"10.0.10586.305"))
    {
      Vulnerable_range2 = "10.0.10586.0 - 10.0.10586.305";
      VULN2 = TRUE ;
    }
  }
}



if(VULN1)
{
  report = 'File checked:     ' + sysPath + "\System32\Win32k.sys" + '\n' +
           'File version:     ' + dllVer1  + '\n' +
           'Vulnerable range: ' + Vulnerable_range1 + '\n' ;
  security_message(data:report);
  exit(0);
}

if(VULN2)
{
  report = 'File checked:     ' + sysPath + "\System32\Dxgkrnl.sys" + '\n' +
           'File version:     ' + dllVer2  + '\n' +
           'Vulnerable range: ' + Vulnerable_range2 + '\n' ;
  security_message(data:report);
  exit(0);
}

exit(0);

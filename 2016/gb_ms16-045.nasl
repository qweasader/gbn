# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807661");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2016-0088", "CVE-2016-0089", "CVE-2016-0090");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-12 22:11:00 +0000 (Fri, 12 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-04-13 08:09:15 +0530 (Wed, 13 Apr 2016)");
  script_name("Microsoft Windows Hyper-V Multiple Vulnerabilities (3143118)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-045");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to
  when Windows Hyper-V on a host operating system fails to properly validate
  input from an authenticated user on a guest operating system.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to
  execute arbitrary code on the host operating system, also could gain access to
  information on the Hyper-V host operating system.");

  script_tag(name:"affected", value:"- Microsoft Windows 8.1 x64

  - Microsoft Windows Server 2012/2012R2

  - Microsoft Windows 10 x64");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3143118");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-045");

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

if(hotfix_check_sp(win2012:1, win2012R2:1, win8_1x64:1, win10x64:1) <= 0){
  exit(0);
}

sysPath1 = smb_get_systemroot();
if(!sysPath1){
  exit(0);
}

sysVer = fetch_file_version(sysPath:sysPath1, file_name:"System32\Vmsif.dll");
if(!sysVer){
  exit(0);
}

if (sysVer =~ "^(6\.3\.9600\.1)"){
  Vulnerable_range = "Less than 6.3.9600.18258";
}
else if (sysVer =~ "^(10\.0\.10240)"){
  Vulnerable_range = "Less than 10.0.10240.16766";
}


#if(hotfix_check_sp(win2012:1) > 0)
#{
   #Vmswitch.sys file has dynamic path.
#}

else if(hotfix_check_sp(win8_1x64:1, win2012R2:1) > 0)
{
  if(version_is_less(version:sysVer, test_version:"6.3.9600.18258")){
    VULN = TRUE ;
  }
}

if(hotfix_check_sp(win10x64:1) > 0)
{
  if(version_is_less(version:sysVer, test_version:"10.0.10240.16725")){
     VULN = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + sysPath1 + "\system32\Vmsif.dll" + '\n' +
           'File version:     ' + sysVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}

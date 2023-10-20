# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811828");
  script_version("2023-07-14T16:09:27+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2017-8759");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-14 02:29:00 +0000 (Sun, 14 Jan 2018)");
  script_tag(name:"creation_date", value:"2017-09-14 11:19:26 +0530 (Thu, 14 Sep 2017)");
  script_name("Microsoft .NET Framework Remote Code Execution Vulnerability (KB4040972 and KB4040971)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Security Updates KB4040972 and KB4040971.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw exists due to Microsoft .NET Framework
  processes untrusted input.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to take control of an affected system. An attacker could then install
  programs, view, change, or delete data, or create new accounts with full user
  rights. Users whose accounts are configured to have fewer user rights on the
  system could be less impacted than users who operate with administrative user
  rights.");

  script_tag(name:"affected", value:"- Microsoft .NET Framework 4.6

  - Microsoft .NET Framework 4.6.1

  - Microsoft .NET Framework 4.6.2

  - Microsoft .NET Framework 4.7");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4040972");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4040971");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4040972");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1, win2012:1) <= 0){
  exit(0);
}

key = "SOFTWARE\Microsoft\ASP.NET\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  dotPath = registry_get_sz(key:key + item, item:"Path");
  if(dotPath && "\Microsoft.NET\Framework" >< dotPath)
  {
    sysdllVer = fetch_file_version(sysPath:dotPath, file_name:"system.dll");
    if(!sysdllVer){
      exit(0);
    }

    ## .NET Framework 4.6/4.6.1/4.6.2/4.7 for Windows 8.1, Windows Server 2012 R2 and Windows Server 2012
    if(version_in_range(version:sysdllVer, test_version:"4.6", test_version2:"4.7.2113"))
    {
      report = 'File checked:     ' + dotPath + "\system.dll" + '\n' +
               'File version:     ' + sysdllVer  + '\n' +
               'Vulnerable range: 4.6 - 4.7.2113\n' ;
      security_message(data:report);
      exit(0);
    }
  }
}

# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806183");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2015-6124", "CVE-2015-6172");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-12-09 13:16:16 +0530 (Wed, 09 Dec 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Word Multiple Remote Code Execution Vulnerabilities (3116111)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS15-131.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaws are due to improper handling of files
  in the memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to run arbitrary code in the context of the current user and
  to perform actions in the security context of the current user.");

  script_tag(name:"affected", value:"- Microsoft Word 2007 Service Pack 3 and prior

  - Microsoft Word 2010 Service Pack 2 and prior

  - Microsoft Word 2013 Service Pack 1 and prior

  - Microsoft Word 2016 Service Pack 1 and prior");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3101532");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3114342");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3114458");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/library/security/MS15-131");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Word/Version");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms15-131");
  exit(0);
}

include("version_func.inc");

##word 2007, 2010, 2013, 2016
exeVer = get_kb_item("SMB/Office/Word/Version");
if(!exeVer){
  exit(0);
}

exePath = get_kb_item("SMB/Office/Word/Install/Path");
if(!exePath){
  exePath = "Unable to fetch the install path";
}

if(exeVer && exeVer =~ "^(12|14|15|16).*")
{
  if(exeVer =~ "^12"){
    Vulnerable_range  =  "12 - 12.0.6740.4999";
  }
  else if(exeVer =~ "^14"){
    Vulnerable_range  =  "14 - 14.0.7164.5000";
  }
  else if(exeVer =~ "^15"){
    Vulnerable_range  =  "15 - 15.0.4779.1000";
  }
  else if(exeVer =~ "^16"){
    Vulnerable_range  =  "16 - 16.0.4312.1000";
  }

  if(version_in_range(version:exeVer, test_version:"12.0", test_version2:"12.0.6740.4999") ||
     version_in_range(version:exeVer, test_version:"14.0", test_version2:"14.0.7164.5000") ||
     version_in_range(version:exeVer, test_version:"15.0", test_version2:"15.0.4779.1000") ||
     version_in_range(version:exeVer, test_version:"16.0", test_version2:"16.0.4312.1000"))
  {
     report = 'File checked:     ' + exePath + "winword.exe"  + '\n' +
              'File version:     ' + exeVer  + '\n' +
              'Vulnerable range: ' + Vulnerable_range + '\n' ;
     security_message(data:report);
     exit(0);
  }
}

# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806121");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2015-2555", "CVE-2015-2557", "CVE-2015-2558");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-10-14 10:33:15 +0530 (Wed, 14 Oct 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Visio Multiple Remote Code Execution Vulnerabilities (3096440)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS15-110");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaws are due to improper handling of files
  in the memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to run arbitrary code in the context of the current user and
  to perform actions in the security context of the current user.");

  script_tag(name:"affected", value:"- Microsoft Visio 2007

  - Microsoft Visio 2010");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3096440");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3085542");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3085514");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/library/security/MS15-110");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms15-110");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                             "\App Paths\visio.exe", item:"Path");
if(!sysPath){
  exit(0);
}

excelVer = fetch_file_version(sysPath:sysPath, file_name:"visio.exe");
if(excelVer =~ "^(12|14)\..*")
{
  if(excelVer =~ "^12"){
    Vulnerable_range  =  "12 - 12.0.6727.5000";
  }
  else if(excelVer =~ "^14"){
    Vulnerable_range  =  "14 - 14.0.7160.4999";
  }

  if(version_in_range(version:excelVer, test_version:"12.0", test_version2:"12.0.6727.4999") ||
     version_in_range(version:excelVer, test_version:"14.0", test_version2:"14.0.7160.4999"))
  {
    report = 'File checked:  visio.exe' + '\n' +
             'File version:     ' + excelVer  + '\n' +
             'Vulnerable range: ' + Vulnerable_range + '\n' ;

    security_message(port:0, data:report);
    exit(0);
  }
}

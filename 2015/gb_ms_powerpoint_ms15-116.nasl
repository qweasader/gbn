# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806164");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2015-2503");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-11-11 15:31:03 +0530 (Wed, 11 Nov 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office PowerPoint Privilege Elevation Vulnerability (3104540)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS15-116.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An elevation of privilege vulnerability
  exists in Microsoft Office software when an attacker instantiates an affected
  Office application via a COM control.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain elevated privileges and break out of the Internet Explorer
  sandbox.");

  script_tag(name:"affected", value:"- Microsoft PowerPoint 2007 Service Pack 3 and prior

  - Microsoft PowerPoint 2010 Service Pack 2 and prior

  - Microsoft PowerPoint 2013 Service Pack 1 and prior

  - Microsoft PowerPoint 2016 Service Pack 1 and prior");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3085548");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3085594");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3101359");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/library/security/MS15-116");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Office/Ver", "SMB/Office/PowerPnt/Version");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms15-116");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

pptVer = get_kb_item("SMB/Office/PowerPnt/Version");
if(!pptVer){
  exit(0);
}

# Office Power Point for 2007/2010/2013/2016
path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                          item:"ProgramFilesDir");
if(!path){
  exit(0);
}

foreach ver (make_list("OFFICE12", "OFFICE14", "OFFICE15", "root\OFFICE16"))
{
  offPath = path + "\Microsoft Office\" + ver ;

  exeVer  = fetch_file_version(sysPath:offPath, file_name:"ppcore.dll");
  if(exeVer && exeVer =~ "^(12|14|15|16).*")
  {
    if(exeVer =~ "^12"){
      Vulnerable_range  =  "12.0 - 12.0.6727.4999";
    }
    else if(exeVer =~ "^14"){
      Vulnerable_range  =  "14 - 14.0.7162.4999";
    }
    else if(exeVer =~ "^15"){
      Vulnerable_range  =  "15 - 15.0.4771.0999";
    }
    else if(exeVer =~ "^16"){
      Vulnerable_range  =  "16 - 16.0.4300.1000";
    }

    if(version_in_range(version:exeVer, test_version:"12.0", test_version2:"12.0.6727.4999") ||
       version_in_range(version:exeVer, test_version:"14.0", test_version2:"14.0.7162.4999") ||
       version_in_range(version:exeVer, test_version:"15.0", test_version2:"15.0.4771.0999") ||
       version_in_range(version:exeVer, test_version:"16.0", test_version2:"16.0.4300.1000"))
    {
       if("root" >< ver){
         offPath = path + "\Microsoft Office" + "\\r" +ver;
       }
       report = 'File checked:    ' +offPath+ "\ppcore.dll"  + '\n' +
                'File version:     ' + exeVer  + '\n' +
                'Vulnerable range: ' + Vulnerable_range + '\n' ;
       security_message(data:report);
       exit(0);
    }
  }
}

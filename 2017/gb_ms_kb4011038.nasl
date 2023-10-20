# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811676");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-09-13 10:51:35 +0530 (Wed, 13 Sep 2017)");
  script_name("Microsoft Office 2016 Defense in Depth Update (KB4011038)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4011038");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Microsoft has released an update for Microsoft
  Office that provides enhanced security as a defense-in-depth measure.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to
  affect on integrity, availability and confidentiality of the system.");

  script_tag(name:"affected", value:"Microsoft Office 2016.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4011038");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");


officeVer = get_kb_item("MS/Office/Ver");
if(!officeVer){
  exit(0);
}

propath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                            item:"ProgramFilesDir");
if(!propath){
  exit(0);
}

##For office
if(officeVer =~ "^16\.")
{
  ## Office Path
  offPath = propath + "\Microsoft Office\root\VFS\ProgramFilesCommonX86\Microsoft Shared\Office16";

  offexeVer = fetch_file_version(sysPath:offPath, file_name:"mso99lres.dll");

  if(offexeVer && version_in_range(version:offexeVer, test_version:"16.0", test_version2:"16.0.4519.0999"))
  {
    report = 'File checked:     ' + offPath + "\mso99lres.dll" + '\n' +
             'File version:     ' + offexeVer  + '\n' +
             'Vulnerable range: ' + "16.0 - 16.0.4519.0999" + '\n' ;
    security_message(data:report);
    exit(0);
  }
}
exit(0);

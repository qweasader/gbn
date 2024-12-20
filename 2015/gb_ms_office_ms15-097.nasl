# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806116");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2015-2510");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-09-09 14:09:01 +0530 (Wed, 09 Sep 2015)");
  script_name("Microsoft Graphics Component Buffer Overflow Vulnerability (3089656)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS15-097.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to improper handling of
  TrueType fonts.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to execute arbitrary code on the affected system.");

  script_tag(name:"affected", value:"- Microsoft Office 2007 Service Pack 3

  - Microsoft Office 2010 Service Pack 2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3085546");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3085529");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS15-097");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

officeVer = get_kb_item("MS/Office/Ver");

## MS Office 2007/2010
if(!officeVer || officeVer !~ "^1[24]\."){
  exit(0);
}

path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"CommonFilesDir");
if(path)
{
  foreach ver (make_list("OFFICE12", "OFFICE14"))
  {
    offPath = path + "\Microsoft Shared\" + ver;
    dllVer = fetch_file_version(sysPath:offPath, file_name:"Ogl.dll");

    if(dllVer)
    {
      if(dllVer =~ "^12"){
        Vulnerable_range  =  "12.0 - 12.0.6728.4999";
      }
      else if(dllVer =~ "^14"){
        Vulnerable_range  =  "14 - 14.0.7157.4999";
      }

      if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.7157.4999") ||
         version_in_range(version:dllVer, test_version:"12.0", test_version2:"12.0.6728.4999"))
      {
        report = 'File checked:     ' + offPath + "\Ogl.dll" + '\n' +
                 'File version:     ' + dllVer  + '\n' +
                 'Vulnerable range: ' + Vulnerable_range + '\n' ;
        security_message(data:report);
        exit(0);
      }
    }
  }
}

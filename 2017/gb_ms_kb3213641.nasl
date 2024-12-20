# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811330");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2017-8676", "CVE-2017-8682", "CVE-2017-8695");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-10 19:58:00 +0000 (Fri, 10 May 2019)");
  script_tag(name:"creation_date", value:"2017-09-13 16:53:34 +0530 (Wed, 13 Sep 2017)");
  script_name("Microsoft Office Multiple Vulnerabilities (KB3213641)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB3213641");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist in,

  - The way that the Windows Graphics Device Interface (GDI) handles objects
    in memory.

  - The Windows font library improperly handles specially crafted embedded
    fonts.

  - When Windows Uniscribe improperly discloses the contents of its memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to potentially sensitive information and execute
  arbitrary code in the context of current user.");

  script_tag(name:"affected", value:"Microsoft Office 2007 Service Pack 3.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3213641");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100755");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100772");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100773");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
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

## MS Office 2007
OfficeVer = get_kb_item("MS/Office/Ver");
if(!OfficeVer  || OfficeVer !~ "^(12\.)"){
  exit(0);
}

msPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                            item:"CommonFilesDir");
if(msPath)
{
  offPath = msPath + "\Microsoft Shared\OFFICE12" ;
  msdllVer = fetch_file_version(sysPath:offPath, file_name:"Ogl.dll");
  if(!msdllVer){
    exit(0);
  }

  if(msdllVer =~ "^(12\.)" && version_is_less(version:msdllVer, test_version:"12.0.6776.5000"))
  {
    report = 'File checked:     ' + offPath + "\Ogl.dll" + '\n' +
             'File version:     ' + msdllVer  + '\n' +
             'Vulnerable range: ' + "12.0 - 12.0.6776.4999" + '\n' ;
    security_message(data:report);
    exit(0);
  }
}

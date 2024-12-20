# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805054");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2015-0085", "CVE-2015-0086", "CVE-2015-0097");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-03-11 12:12:11 +0530 (Wed, 11 Mar 2015)");
  script_name("Microsoft Office Suite Remote Code Execution Vulnerabilities (3038999)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS15-022.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are exists when,

  - The Office software improperly handles objects in memory while parsing
    specially crafted Office files.

  - The Office software fails to properly handle rich text format files in
    memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to run arbitrary code in the context of the current user and
  to perform actions in the security context of the current user.");

  script_tag(name:"affected", value:"- Microsoft Office 2007 Service Pack 3 and prior

  - Microsoft Office 2010 Service Pack 2 and prior

  - Microsoft Office 2013 Service Pack 1 and prior");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2984939");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2956151");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2956076");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2889839");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2883100");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2956138");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/ms15-022");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_ms_office_detection_900025.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Office/Ver");

  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms15-022");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

officeVer = get_kb_item("MS/Office/Ver");

## MS Office 2007,2010, 2015
if(officeVer && officeVer =~ "^1[245]\.")
{
  InsPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"CommonFilesDir");
  if(InsPath)
  {
    foreach offsubver (make_list("Office12", "Office15", "Office14"))
    {
      offPath = InsPath + "\Microsoft Shared\" + offsubver;
      exeVer = fetch_file_version(sysPath:offPath, file_name:"Mso.dll");

      ## For office 2010 Wwlibcxm.dll is mentioned and it is not available so ignoring
      ## version check for office 2010 http://support.microsoft.com/kb/2956138
      if(exeVer)
      {
        if(version_in_range(version:exeVer, test_version:"12.0", test_version2:"12.0.6718.4999") ||
           version_in_range(version:exeVer, test_version:"14.0", test_version2:"14.0.7145.4999") ||
           version_in_range(version:exeVer, test_version:"15.0", test_version2:"15.0.4701.999"))
        {
          security_message( port: 0, data: "The target host was found to be vulnerable" );
          exit(0);
        }
      }
    }
  }
}

## Microsoft Office 2010 Service Pack 1 and prior
## http://support.microsoft.com/kb/2889839
## http://support.microsoft.com/kb/2883100
if(!officeVer || officeVer !~ "^14\."){
  exit(0);
}

comPath = registry_get_sz(key:"SOFTWARE\Microsoft\Office\14.0\Access\InstallRoot", item:"Path");
if(comPath)
{
  ortVer = fetch_file_version(sysPath:comPath, file_name:"Oart.dll");
  ortconVer = fetch_file_version(sysPath:comPath, file_name:"Oartconv.dll");
  if(!isnull(ortVer) || !isnull(ortconVer))
  {
    if(version_in_range(version:ortVer, test_version:"14.0", test_version2:"14.0.7134.4999") ||
       version_in_range(version:ortconVer, test_version:"14.0", test_version2:"14.0.7134.4999"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}

# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806123");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2015-2558");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-10-14 10:56:23 +0530 (Wed, 14 Oct 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Compatibility Pack Remote Code Execution Vulnerabilities (3096440)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS15-110.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Microsoft Excel improperly handles the loading of dynamic link library
    (DLL) files.

  - Improper handling of files in the memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to run arbitrary code and corrupt memory in the context of the
  current user.");

  script_tag(name:"affected", value:"Microsoft Office Compatibility Pack Service Pack 3 and prior.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3096440");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3085618");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/library/security/MS15-110");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/ComptPack/Version", "SMB/Office/XLCnv/Version");

  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms15-110");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");

cmpPckVer = get_kb_item("SMB/Office/ComptPack/Version");
if(cmpPckVer && cmpPckVer =~ "^12\.")
{
  xlcnvVer = get_kb_item("SMB/Office/XLCnv/Version");
  if(xlcnvVer && xlcnvVer =~ "^12\.")
  {
    ## took the file excelconv.exe which is updated after patch
    if(version_in_range(version:xlcnvVer, test_version:"12.0", test_version2:"12.0.6732.4999"))
    {
      report = 'File checked:  excelconv.exe' + '\n' +
               'File version:     ' + xlcnvVer  + '\n' +
               'Vulnerable range: 12.0 - 12.0.6732.4999' + '\n' ;
      security_message(data:report);
      exit(0);
    }
  }
}

# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810690");
  script_version("2023-07-25T05:05:58+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2017-0199");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-04-12 18:22:37 +0530 (Wed, 12 Apr 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Suite Remote Code Execution Vulnerability (KB3178703)");

  script_tag(name:"summary", value:"This host is missing a critical update for
  Microsoft Office Suite according to Microsoft KB3178703.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to error in the way
  Microsoft Office and WordPad parse specially crafted files.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to run arbitrary code in the context of the current user on an
  affected system.");

  script_tag(name:"affected", value:"Microsoft Office 2016.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3178703");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97498");

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

## MS Office
officeVer = get_kb_item("MS/Office/Ver");
if(!officeVer){
  exit(0);
}

commonpath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                            item:"CommonFilesDir");
if(!commonpath){
  exit(0);
}

if(officeVer =~ "^16\.*")
{
  offPath = commonpath + "\Microsoft Shared\Office16";
  offdllVer = fetch_file_version(sysPath:offPath, file_name:"mso30win32client.dll");
  if(offdllVer)
  {
    if(version_in_range(version:offdllVer, test_version:"16.0", test_version2:"16.0.4522.0999"))
    {
      report = 'File checked:     ' + offPath + "\mso30win32client.dll" + '\n' +
               'File version:     ' + offdllVer  + '\n' +
               'Vulnerable range: ' + "16.0 - 16.0.4522.0999" + '\n' ;
      security_message(data:report);
      exit(0);
    }
  }
}

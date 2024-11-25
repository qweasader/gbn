# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805062");
  script_version("2024-07-25T05:05:41+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2015-1641", "CVE-2015-1650", "CVE-2015-1649", "CVE-2015-1651");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-07-25 05:05:41 +0000 (Thu, 25 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-24 17:06:41 +0000 (Wed, 24 Jul 2024)");
  script_tag(name:"creation_date", value:"2015-04-15 11:11:20 +0530 (Wed, 15 Apr 2015)");
  script_name("Microsoft Office Word Remote Code Execution Vulnerabilities (3048019)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS15-033.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are exists when,

  - The Office software improperly handles objects in memory while parsing
    specially crafted Office files.

  - The Office software fails to properly handle rich text format files in
    memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to run arbitrary code in the context of the current user and
  to perform actions in the security context of the current user.");

  script_tag(name:"affected", value:"- Microsoft Word 2010

  - Microsoft Word 2013 and

  - Microsoft Word 2007 Service Pack 3 and prior");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/2965284");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/2965224");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/2553428");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/ms15-033");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Word/Version");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms15-033");
  exit(0);
}

include("version_func.inc");

winwordVer = get_kb_item("SMB/Office/Word/Version");

## Microsoft Office Word 2007/2010/2013
if(winwordVer && winwordVer =~ "^(12|14|15).*")
{
  ##  15 < 15.0.4711.1001
  if(version_in_range(version:winwordVer, test_version:"12.0", test_version2:"12.0.6720.4999") ||
     version_in_range(version:winwordVer, test_version:"14.0", test_version2:"14.0.7147.4999") ||
     version_in_range(version:winwordVer, test_version:"15.0", test_version2:"15.0.4711.1000"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

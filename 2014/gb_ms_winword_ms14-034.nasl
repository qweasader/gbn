# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804457");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2014-2778");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-06-11 08:36:13 +0530 (Wed, 11 Jun 2014)");
  script_name("Microsoft Office Word Remote Code Execution Vulnerability (2969261)");

  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS14-034.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an unspecified error when processing embedded fonts,
  which can be exploited to execute arbitrary code.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute the arbitrary
  code, cause memory corruption and compromise the system.");

  script_tag(name:"affected", value:"Microsoft Word 2007 Service Pack 3 and prior.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2880515");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67896");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms14-034");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Word/Version");

  exit(0);
}

include("secpod_reg.inc");
include("version_func.inc");

winwordVer = get_kb_item("SMB/Office/Word/Version");

## Microsoft Office Word 2003/2007/2010
if(winwordVer && winwordVer =~ "^12\.")
{
  if(version_in_range(version:winwordVer, test_version:"12.0", test_version2:"12.0.6700.4999"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901040");
  script_version("2024-06-21T05:05:42+0000");
  script_tag(name:"last_modification", value:"2024-06-21 05:05:42 +0000 (Fri, 21 Jun 2024)");
  script_tag(name:"creation_date", value:"2009-10-14 16:47:08 +0200 (Wed, 14 Oct 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0901", "CVE-2009-2493", "CVE-2009-2495");
  script_name("Microsoft ATL ActiveX Controls for MS Office Could Allow Remote Code Execution (973965)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Prdts/Installed");

  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/2895");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35828");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35830");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35832");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-060");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  code with SYSTEM privileges, and can cause Denial of Service.");

  script_tag(name:"affected", value:"- Microsoft Office Outlook 2002/2003/2007

  - Microsoft Office Visio Viewer 2007");

  script_tag(name:"insight", value:"Multiple flaws are due to

  - Error in the Microsoft Active Template Library (ATL) within the ATL headers
    that handle instantiation of an object from data streams.

  - Error in the ATL headers, which could allow a string to be read with no ending
    NULL bytes, which could allow an attacker to manipulate a string to read extra
    data beyond the end of the string and thus disclose information in memory.

  - Error in the Microsoft Active Template Library (ATL) headers, which could allow
    attackers to call 'VariantClear()' on a variant that has not been correctly
    initialized, leading to arbitrary code execution.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS09-060.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

visVer = get_kb_item("SMB/Office/Outlook/Version");
if(visVer =~ "^1[0-2]\.")
{
  if(version_in_range(version:visVer, test_version:"10.0", test_version2:"10.0.6855") ||
     version_in_range(version:visVer, test_version:"11.0", test_version2:"11.0.8311") ||
     version_in_range(version:visVer, test_version:"12.0", test_version2:"12.0.6514.4999"))
  {
    report = report_fixed_ver(installed_version:visVer, vulnerable_range:"10.0-10.0.6855, 11.0 - 11.0.8311, 12.0 - 12.0.6514.4999");
    security_message(port:0, data:report);
    exit(0);
  }
}

visioVer = get_kb_item("SMB/Office/VisioViewer/Ver");
if(visioVer =~ "^12\.")
{
  if(version_in_range(version:visioVer, test_version:"12.0", test_version2:"12.0.6513.4999")){
    report = report_fixed_ver(installed_version:visioVer, vulnerable_range:"12.0 - 12.0.6513.4999");
    security_message(port:0, data:report);
  }
}

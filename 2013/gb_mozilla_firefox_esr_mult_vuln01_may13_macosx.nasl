# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803608");
  script_version("2024-07-17T05:05:38+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2013-1681", "CVE-2013-1680", "CVE-2013-1679", "CVE-2013-1678",
                "CVE-2013-1677", "CVE-2013-1676", "CVE-2013-1675", "CVE-2013-1674",
                "CVE-2013-1672", "CVE-2013-1670", "CVE-2013-0801");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-07-17 05:05:38 +0000 (Wed, 17 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 17:35:45 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2013-05-27 12:50:31 +0530 (Mon, 27 May 2013)");
  script_name("Mozilla Firefox ESR Multiple Vulnerabilities -01 (May 2013) - Mac OS X");
  script_xref(name:"URL", value:"http://secunia.com/advisories/53410");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59855");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59858");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59859");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59860");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59861");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59862");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59863");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59864");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59865");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59868");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59872");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1028555");
  script_xref(name:"URL", value:"http://www.dhses.ny.gov/ocs/advisories/2013/2013-051.cfm");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox-ESR/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code,
  memory corruption, bypass certain security restrictions and compromise
  a user's system.");
  script_tag(name:"affected", value:"Mozilla Firefox ESR version before 17.x before 17.0.6 on Mac OS X");
  script_tag(name:"insight", value:"- Unspecified vulnerabilities in the browser engine.

  - The Chrome Object Wrapper (COW) implementation does not prevent
    acquisition of chrome privileges.

  - 'nsDOMSVGZoomEvent::mPreviousScale' and 'nsDOMSVGZoomEvent::mNewScale'
    functions do not initialize data structures.

  - Errors in 'SelectionIterator::GetNextSegment',
   'gfxSkipCharsIterator::SetOffsets' and '_cairo_xlib_surface_add_glyph'
   functions.

  - Use-after-free vulnerabilities in following functions,
    'nsContentUtils::RemoveScriptBlocker', 'nsFrameList::FirstChild', and
    'mozilla::plugins::child::_geturlnotify'.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR version 17.0.6 or later.");
  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

ffVer = get_kb_item("Mozilla/Firefox-ESR/MacOSX/Version");

if(ffVer && ffVer =~ "^(17.0)")
{
  if(version_in_range(version:ffVer, test_version:"17.0", test_version2:"17.0.5"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

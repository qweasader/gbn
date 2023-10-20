# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800344");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-05-07 14:39:04 +0200 (Thu, 07 May 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1313");
  script_name("Mozilla Firefox DoS Vulnerability May-09 (Windows)");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=490233");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34743");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Apr/1022126.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-23.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary code which
  results in memory corruption.");

  script_tag(name:"affected", value:"Firefox version prior to 3.0.10 on Windows.");

  script_tag(name:"insight", value:"The flaw is due to error in nsTextFrame::ClearTextRun function in
  layout/generic/nsTextFrameThebes.cpp via unspecified vectors.");

  script_tag(name:"solution", value:"Upgrade to Firefox version 3.0.10.");

  script_tag(name:"summary", value:"Mozilla Firefox browser is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Win/Ver");
if(!ffVer){
  exit(0);
}

if(version_is_less(version:ffVer, test_version:"3.0.10")){
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"3.0.10");
  security_message(port: 0, data: report);
}

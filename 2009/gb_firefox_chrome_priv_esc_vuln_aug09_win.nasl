# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800859");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-08-07 07:29:21 +0200 (Fri, 07 Aug 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2665");
  script_name("Mozilla Firefox Chrome Privilege Escalation Vulnerability Aug-09 (Windows)");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=498897");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35928");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-46.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation will let attacker to execute arbitrary JavaScript with
  chrome privileges when certain add-ons are enabled.");

  script_tag(name:"affected", value:"Firefox version 3.5 before 3.5.2 on Windows.");

  script_tag(name:"insight", value:"Error in 'nsDocument::SetScriptGlobalObject()' function in 'nsDocument.cpp' in
  content/base/src/ which does not properly handle a Link HTTP header, which
  allows remote attackers to execute arbitrary JavaScript with chrome
  privileges via a crafted web page, related to an incorrect security wrapper.");

  script_tag(name:"solution", value:"Upgrade to Firefox version 3.5.2.");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to Chrome Privilege Escalation vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Win/Ver");
if(!ffVer){
  exit(0);
}

if(version_in_range(version:ffVer, test_version:"3.5", test_version2:"3.5.1")) {
  report = report_fixed_ver(installed_version:ffVer, vulnerable_range:"3.5 - 3.5.1");
  security_message(port: 0, data: report);
}

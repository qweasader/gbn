# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802989");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2012-5354", "CVE-2012-3989", "CVE-2012-3985", "CVE-2012-3984");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-10-15 16:41:45 +0530 (Mon, 15 Oct 2012)");
  script_name("Mozilla Firefox Multiple Vulnerabilities - Oct 12 (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50856");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55856");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50935");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-76.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-75.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-80.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to conduct cross-site scripting,
  clickjacking attacks or cause a denial of service or possibly execute
  arbitrary code.");
  script_tag(name:"affected", value:"Mozilla Firefox versions before 16.0 on Windows");
  script_tag(name:"insight", value:"The flaws are due to

  - An error while handling navigation away from a web page that has multiple
    menus of SELECT elements active, which allows remote attackers to conduct
    clickjacking attacks.

  - An invalid cast when using the instance of operator on certain types of
    JavaScript objects.

  - An error when implementing the HTML5 Same Origin Policy, which allows
    remote attackers to conduct cross-site scripting (XSS) attacks by
    leveraging initial-origin access after document.domain has been set.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 16.0 or later.");
  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");


ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  if(version_is_less(version:ffVer, test_version:"16.0"))
  {
    report = report_fixed_ver(installed_version:ffVer, fixed_version:"16.0");
    security_message(port:0, data:report);
    exit(0);
  }
}

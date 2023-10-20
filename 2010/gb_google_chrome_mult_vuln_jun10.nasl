# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800785");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-06-04 09:43:24 +0200 (Fri, 04 Jun 2010)");
  script_cve_id("CVE-2010-2105", "CVE-2010-2106", "CVE-2010-2107",
                "CVE-2010-2108", "CVE-2010-2109", "CVE-2010-2110");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Google Chrome multiple vulnerabilities - June 10");
  script_xref(name:"URL", value:"http://code.google.com/p/chromium/issues/detail?id=41469");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2010/05/stable-channel-update.html");

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow the attackers to cause denial of service.");
  script_tag(name:"affected", value:"Google Chrome version prior to 5.0.375.55");
  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An error in canonicalization of URLs, which does not properly follow the
    safe browsing 'specification&qts' requirements for canonicalization of
    'URLs'.

  - A memory error when processing vectors related to the Safe Browsing
    functionality.

  - Unspecified errors when processing vectors involving 'unload' event handlers,
    which allow remote attackers to spoof the URL bar.

  - Unspecified errors when processing unknown vectors, which allows remote
    attackers to bypass the 'whitelist-mode' plugin blocker.

  - Unspecified errors when handling the vectors related to the 'drag + drop'
    functionality allows remote attackers to cause a denial of service.

  - It does not properly execute 'JavaScript' code in the extension context,
    which has unspecified impact and remote attack vectors.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 5.0.375.55 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");
  script_xref(name:"URL", value:"http://www.google.com/chromeVer");
  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"5.0.375.55")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"5.0.375.55");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

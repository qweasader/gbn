# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902905");
  script_version("2024-02-08T14:36:53+0000");
  script_cve_id("CVE-2011-3924", "CVE-2011-3925", "CVE-2011-3926", "CVE-2011-3927",
                "CVE-2011-3928");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-01-25 13:12:13 +0530 (Wed, 25 Jan 2012)");
  script_name("Google Chrome Multiple Vulnerabilities (Jan 2012) - Mac OS X");
  script_xref(name:"URL", value:"http://secunia.com/advisories/47694/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51641");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1026569");
  script_xref(name:"URL", value:"http://code.google.com/p/chromium/issues/detail?id=108461");
  script_xref(name:"URL", value:"http://securityorb.com/2012/01/google-releases-chrome-16-0-912-77/");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2012/01/stable-channel-update_23.html");

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code or
  cause a denial of service.");
  script_tag(name:"affected", value:"Google Chrome version prior to 16.0.912.77 on Mac OS X");
  script_tag(name:"insight", value:"Multiple flaws are due to an:

  - Use-after-free error and it is related to DOM selections and DOM handling.

  - Use-after-free error in the Safe Browsing feature and it is related to
    a navigation entry and an interstitial page.

  - Heap-based buffer overflow in the tree builder, allows remote attackers
    to cause a denial of service.

  - Error in Skia, does not perform all required initialization of values.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 16.0.912.77 or later.");
  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/MacOSX/Version");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"16.0.912.77")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"16.0.912.77");
  security_message(port:0, data:report);
}

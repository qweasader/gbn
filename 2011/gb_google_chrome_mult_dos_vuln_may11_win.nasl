# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801890");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-05-26 10:47:46 +0200 (Thu, 26 May 2011)");
  script_cve_id("CVE-2011-1799", "CVE-2011-1800");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Google Chrome Multiple Denial of Service Vulnerabilities - May11 (Windows)");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2011/05/stable-channel-update.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47828");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47830");

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to execute arbitrary code in
  the context of the user running the application. Failed attacks may cause
  denial of service conditions.");
  script_tag(name:"affected", value:"Google Chrome version prior to 11.0.696.68 on Windows");
  script_tag(name:"insight", value:"- Bad variable casts in Chromium WebKit glue allows remote attackers to cause
    a denial of service or possibly have unspecified other impact.

  - Multiple integer overflows in the SVG Filters implementation in WebCore in
    WebKit allows remote attackers to cause a denial of service or possibly
    have unspecified other impact via unknown vectors.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 11.0.696.68 or later.");
  script_tag(name:"summary", value:"Google Chrome is prone to multiple denial of service vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"11.0.696.68")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"11.0.696.68");
  security_message(port: 0, data: report);
}

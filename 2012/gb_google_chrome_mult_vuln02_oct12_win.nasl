# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802473");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2012-5112", "CVE-2012-5376");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-10-15 11:14:26 +0530 (Mon, 15 Oct 2012)");
  script_name("Google Chrome Multiple Vulnerabilities-02 Oct12 (Windows)");
  script_xref(name:"URL", value:"http://blog.chromium.org/2012/10/pwnium-2-results-and-wrap-up_10.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55867");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2012/10/stable-channel-update_6105.html");

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow the attackers to execute arbitrary code
  and cause a denial of service.");
  script_tag(name:"affected", value:"Google Chrome version prior to 22.0.1229.94 on Windows");
  script_tag(name:"insight", value:"Multiple flaws are due to

  - Use-after-free error in the SVG implementation in WebKit, allows remote
    attackers to execute arbitrary code via unspecified vectors.

  - An error in Inter-process Communication (IPC) implementation, allows
    remote attackers to bypass intended sandbox restrictions and write to
    arbitrary files by leveraging access to a renderer process.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 22.0.1229.94 or later.");
  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"22.0.1229.94")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"22.0.1229.94");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

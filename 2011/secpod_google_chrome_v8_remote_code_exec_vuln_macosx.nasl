# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902637");
  script_version("2024-02-15T05:05:39+0000");
  script_cve_id("CVE-2011-3900");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-11-21 17:55:43 +0530 (Mon, 21 Nov 2011)");
  script_name("Google Chrome V8 Remote Code Execution Vulnerability - Mac OS X");
  script_xref(name:"URL", value:"http://secunia.com/advisories/46889/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50701");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2011/11/stable-channel-update_16.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code,
  cause a denial of service.");
  script_tag(name:"affected", value:"Google Chrome version prior to 15.0.874.121 on Mac OS X");
  script_tag(name:"insight", value:"The flaw is due to an out-of-bounds write operation error in V8
  (JavaScript engine) causing memory corruption.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 15.0.874.121 or later.");
  script_tag(name:"summary", value:"Google Chrome is prone to a remote code execution (RCE) vulnerability.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/MacOSX/Version");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"15.0.874.121")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"15.0.874.121");
  security_message(port: 0, data: report);
}

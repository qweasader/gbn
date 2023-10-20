# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801475");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-11-02 18:01:36 +0100 (Tue, 02 Nov 2010)");
  script_cve_id("CVE-2010-3765");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Mozilla Firefox Unspecified Vulnerability Oct-10 (Windows)");
  script_xref(name:"URL", value:"http://isc.sans.edu/diary.html?storyid=9817");
  script_xref(name:"URL", value:"http://www.norman.com/about_norman/press_center/news_archive/2010/129223/");
  script_xref(name:"URL", value:"http://blog.mozilla.com/security/2010/10/26/critical-vulnerability-in-firefox-3-5-and-firefox-3-6/");

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary
code via unknown vectors.");
  script_tag(name:"affected", value:"Mozilla Firefox version 3.5.x through 3.5.14
Mozilla Firefox version 3.6.x through 3.6.11");
  script_tag(name:"insight", value:"The flaw is due to unspecified vulnerability, when JavaScript is
enabled.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 3.5.15 or 3.6.12.");
  script_tag(name:"summary", value:"Mozilla Firefox is prone to an unspecified vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

fpVer = get_kb_item("Firefox/Win/Ver");
if(!fpVer){
  exit(0);
}

if(version_in_range(version:fpVer, test_version:"3.5.0", test_version2:"3.5.14")||
   version_in_range(version:fpVer, test_version:"3.6.0", test_version2:"3.6.11")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802835");
  script_version("2024-02-26T05:06:11+0000");
  script_cve_id("CVE-2011-3066", "CVE-2011-3067", "CVE-2011-3068", "CVE-2011-3069",
                "CVE-2011-3070", "CVE-2011-3071", "CVE-2011-3072", "CVE-2011-3073",
                "CVE-2011-3074", "CVE-2011-3075", "CVE-2011-3076", "CVE-2011-3077",
                "CVE-2012-0724", "CVE-2012-0725");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-26 05:06:11 +0000 (Mon, 26 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-04-18 11:25:47 +0530 (Wed, 18 Apr 2012)");
  script_name("Google Chrome < 18.0.1025.151 Multiple Vulnerabilities (Apr 2012) - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/48732/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52913");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52914");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52916");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1026892");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2012/04/stable-and-beta-channel-updates.html");

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to inject scripts, bypass
  certain security restrictions, execute arbitrary code in the context of the
  browser or cause a denial of service.");
  script_tag(name:"affected", value:"Google Chrome version prior to 18.0.1025.151 on Windows");
  script_tag(name:"insight", value:"The flaws are due to

  - Unspecified errors in flash player, allows to corrupt memory in the
    chrome interface.

  - An out of bounds read error when handling Skia clipping.

  - Errors in the cross origin policy when handling iframe replacement and
    parenting pop up windows.

  - Multiple use after free errors when handling line boxes, v8 bindings,
    HTMLMediaElement, SVG resources, media content, focus events and when
    applying style commands.

  - A read after free error in the script bindings.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 18.0.1025.151 or later.");
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

if(version_is_less(version:chromeVer, test_version:"18.0.1025.151")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

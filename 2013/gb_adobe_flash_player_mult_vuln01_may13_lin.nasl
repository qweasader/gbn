# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803498");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2013-3335", "CVE-2013-3334", "CVE-2013-3333", "CVE-2013-3332",
                "CVE-2013-3331", "CVE-2013-3330", "CVE-2013-3329", "CVE-2013-3328",
                "CVE-2013-3327", "CVE-2013-3326", "CVE-2013-3325", "CVE-2013-3324",
                "CVE-2013-2728");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-05-21 13:26:52 +0530 (Tue, 21 May 2013)");
  script_name("Adobe Flash Player Multiple Vulnerabilities -01 May 13 (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/53419");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59889");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59890");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59891");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59892");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59893");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59894");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59895");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59896");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59897");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59898");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59899");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59900");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59901");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb13-14.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code on the target system or cause a denial of service (memory corruption)
  via unspecified vectors.");
  script_tag(name:"affected", value:"Adobe Flash Player version before 10.3.183.76 and 11.x before 11.2.202.281
  on Linux");
  script_tag(name:"insight", value:"Multiple memory corruption flaws due to improper sanitation of user
  supplied input via a file.");
  script_tag(name:"solution", value:"Update to Adobe Flash Player version 10.3.183.86 or 11.2.202.285 or later.");
  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

playerVer = get_kb_item("AdobeFlashPlayer/Linux/Ver");
if(playerVer)
{
  if(version_is_less(version:playerVer, test_version:"10.3.183.75") ||
     version_in_range(version:playerVer, test_version:"11.0", test_version2:"11.2.202.280"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

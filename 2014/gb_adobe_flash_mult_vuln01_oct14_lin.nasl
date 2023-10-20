# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805004");
  script_version("2023-07-26T05:05:09+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2014-0558", "CVE-2014-0564", "CVE-2014-0569", "CVE-2014-8439");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-10-20 12:43:30 +0530 (Mon, 20 Oct 2014)");

  script_name("Adobe Flash Player Multiple Vulnerabilities(APSB14-22)-(Linux)");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Two unspecified errors can be exploited to corrupt memory and subsequently
    execute arbitrary code.

  - An integer overflow error can be exploited to execute arbitrary code.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code and compromise a user's system.");

  script_tag(name:"affected", value:"Adobe Flash Player before 11.2.202.411
  on Linux");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version
  11.2.202.411 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://secunia.com/advisories/59729");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70437");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70441");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70442");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71289");
  script_xref(name:"URL", value:"http://helpx.adobe.com/security/products/flash-player/apsb14-22.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Linux/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!playerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:playerVer, test_version:"11.2.202.411"))
{
  report = report_fixed_ver(installed_version:playerVer, fixed_version:"11.2.202.411");
  security_message(port:0, data:report);
  exit(0);
}

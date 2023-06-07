# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804795");
  script_version("2023-03-24T10:19:42+0000");
  script_cve_id("CVE-2014-0573", "CVE-2014-0574", "CVE-2014-0576", "CVE-2014-0577",
                "CVE-2014-0581", "CVE-2014-0582", "CVE-2014-0583", "CVE-2014-0584",
                "CVE-2014-0585", "CVE-2014-0586", "CVE-2014-0588", "CVE-2014-0589",
                "CVE-2014-0590", "CVE-2014-8437", "CVE-2014-8438", "CVE-2014-8440",
                "CVE-2014-8441", "CVE-2014-8442");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-03-24 10:19:42 +0000 (Fri, 24 Mar 2023)");
  script_tag(name:"creation_date", value:"2014-11-14 11:47:37 +0530 (Fri, 14 Nov 2014)");
  script_name("Adobe Flash Player Multiple Vulnerabilities(APSB14-24)-(Linux)");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An use-after-free error.

  - A double free error.

  - Multiple type confusion errors.

  - An error related to a permission issue.

  - Multiple unspecified errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to disclose potentially sensitive information, bypass certain security
  restrictions, and compromise a user's system.");

  script_tag(name:"affected", value:"Adobe Flash Player version before
  11.2.202.418 on Linux");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version
  11.2.202.418 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://secunia.com/advisories/59978");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71033");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71035");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71036");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71037");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71038");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71039");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71040");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71041");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71042");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71043");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71044");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71045");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71046");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71047");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71048");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71049");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71050");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71051");
  script_xref(name:"URL", value:"http://helpx.adobe.com/security/products/flash-player/apsb14-24.html");

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

if(version_is_less(version:playerVer, test_version:"11.2.202.418"))
{
  report = report_fixed_ver(installed_version:playerVer, fixed_version:"11.2.202.418");
  security_message(port:0, data:report);
  exit(0);
}

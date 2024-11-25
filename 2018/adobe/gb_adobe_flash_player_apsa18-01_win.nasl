# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812683");
  script_version("2024-06-28T15:38:46+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2018-4878", "CVE-2018-4877");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-18 14:26:00 +0000 (Mon, 18 Apr 2022)");
  script_tag(name:"creation_date", value:"2018-02-02 10:51:19 +0530 (Fri, 02 Feb 2018)");
  script_name("Adobe Flash Player Multiple Remote Code Execution Vulnerabilities - Windows");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple remote code execution
  (RCE) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple
  use-after-free errors in the flash player.");

  script_tag(name:"impact", value:"Successful exploitation of these
  vulnerabilities will allow an attacker to execute arbitrary code on
  affected system and take control of the affected system.");

  script_tag(name:"affected", value:"Adobe Flash Player version 28.0.0.137 and
  earlier on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version
  28.0.0.161, or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsa18-01.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102893");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102930");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Win/Installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_less_equal(version:vers, test_version:"28.0.0.137"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"28.0.0.161", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(0);

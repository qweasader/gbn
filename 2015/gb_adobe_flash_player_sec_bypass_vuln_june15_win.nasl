# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805589");
  script_version("2024-02-08T14:36:53+0000");
  script_cve_id("CVE-2015-3097");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-06-15 13:00:22 +0530 (Mon, 15 Jun 2015)");
  script_name("Adobe Flash Player Security Bypass Vulnerability (Jun 2015) - Windows");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The error exists due to improperly selecting
  a random memory address for the Flash heap.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass certain security restrictions and execute arbitrary code on
  affected system.");

  script_tag(name:"affected", value:"Adobe Flash Player before version
  13.0.0.302 and 14.x through 18.x before 18.0.0.203 on Windows-7 64-bit platform.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version
  13.0.0.302 or 18.0.0.203 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-16.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75090");


  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Win/Installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");
include("secpod_reg.inc");

if(hotfix_check_sp(win7x64:2) <= 0){
  exit(0);
}

if(!playerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:playerVer, test_version:"13.0.0.302"))
{
  fix = "13.0.0.302";
  VULN = TRUE;
}

if(version_in_range(version:playerVer, test_version:"14.0", test_version2:"18.0.0.202"))
{
  fix = "18.0.0.203";
  VULN = TRUE;
}

if(VULN)
{
  report = 'Installed version: ' + playerVer + '\n' +
           'Fixed version:     ' + fix + '\n';
  security_message(data:report);
  exit(0);
}

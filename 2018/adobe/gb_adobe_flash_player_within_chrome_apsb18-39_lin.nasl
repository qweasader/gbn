# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_player_chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814291");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2018-15978");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-28 20:01:00 +0000 (Fri, 28 Dec 2018)");
  script_tag(name:"creation_date", value:"2018-11-14 17:24:46 +0530 (Wed, 14 Nov 2018)");
  script_name("Adobe Flash Player Within Google Chrome Security Update (APSB18-39) - Linux");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an out-of-bounds
  read error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to potentially sensitive information.");

  script_tag(name:"affected", value:"Adobe Flash Player prior to 31.0.0.148
  within Google Chrome on Linux.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player for Google
  Chrome 31.0.0.148 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb18-39.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_flash_player_within_google_chrome_detect_lin.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Chrome/Lin/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
playerVer = infos['version'];
path = infos['location'];

if(version_is_less(version:playerVer, test_version:"31.0.0.148"))
{
  report = report_fixed_ver(installed_version:playerVer, fixed_version:"31.0.0.148", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);

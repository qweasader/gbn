# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812252");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2017-11305");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-27 19:24:00 +0000 (Fri, 27 Jan 2023)");
  script_tag(name:"creation_date", value:"2017-12-13 12:28:59 +0530 (Wed, 13 Dec 2017)");
  script_name("Adobe Flash Player Security Updates (APSB17-42) - Linux");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Flaw exists due to a logic error may
  cause the global settings preference file to be reset.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow remote attackers to conduct unintended reset of
  global settings preference file.");

  script_tag(name:"affected", value:"Adobe Flash Player version before
  28.0.0.126 on Linux.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version
  28.0.0.126, or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb17-42.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Linux/Ver");

  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"28.0.0.126"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"28.0.0.126", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(0);

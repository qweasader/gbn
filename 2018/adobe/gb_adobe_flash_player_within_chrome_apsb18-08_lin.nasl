# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_player_chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813208");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2018-4932", "CVE-2018-4933", "CVE-2018-4934", "CVE-2018-4935",
                "CVE-2018-4936", "CVE-2018-4937");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-18 17:17:00 +0000 (Fri, 18 Nov 2022)");
  script_tag(name:"creation_date", value:"2018-04-11 10:51:52 +0530 (Wed, 11 Apr 2018)");
  script_name("Adobe Flash Player Within Google Chrome Security Update (apsb18-08) - Linux");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"- A remote code-execution vulnerability that occurs due to a use-after-free
    condition.

  - Multiple remote code-execution vulnerabilities that occur due to an
    out-of-bounds write error.

  - Multiple information-disclosure vulnerabilities that occur due to an
    out-of-bounds read error.

  - An information-disclosure vulnerability that occurs due to a heap overflow
    condition .");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to gain th control of the affected system. Depending on the
  privileges associated with this application, an attacker could then install
  programs, view, change, or delete data, or create new accounts with full
  user rights.");

  script_tag(name:"affected", value:"Adobe Flash Player prior to 29.0.0.140
  within Google Chrome on Linux.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player for
  Google Chrome 29.0.0.140, or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb18-08.html");

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
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"29.0.0.140"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"29.0.0.140", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);

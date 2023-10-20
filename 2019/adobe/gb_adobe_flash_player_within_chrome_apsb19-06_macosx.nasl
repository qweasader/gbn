# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_player_chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814684");
  script_version("2023-10-13T16:09:03+0000");
  script_cve_id("CVE-2019-7090");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-29 12:36:00 +0000 (Wed, 29 May 2019)");
  script_tag(name:"creation_date", value:"2019-02-13 11:38:50 +0530 (Wed, 13 Feb 2019)");
  script_name("Adobe Flash Player Within Google Chrome Security Update(apsb19-06) - Mac OS X");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an out-of-bounds read
  error.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers
  to conduct information disclosure in the context of the current user.");

  script_tag(name:"affected", value:"Adobe Flash Player prior to 32.0.0.142
  within Google Chrome on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player for Google Chrome
  32.0.0.142, or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb19-06.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("gb_flash_player_within_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Chrome/MacOSX/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"32.0.0.142"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"32.0.0.142", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);

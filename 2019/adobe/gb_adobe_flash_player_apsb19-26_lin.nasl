# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815057");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2019-7837");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-23 13:48:00 +0000 (Thu, 23 May 2019)");
  script_tag(name:"creation_date", value:"2019-05-15 12:42:31 +0530 (Wed, 15 May 2019)");
  script_name("Adobe Flash Player Security Update (APSB19-26) - Linux");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to an use after free vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an use after free
  error.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers
  to conduct arbitrary code execution in the context of current user.");

  script_tag(name:"affected", value:"Adobe Flash Player version before
  32.0.0.192 on Linux.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version
  32.0.0.192, or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb19-26.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Linux/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"32.0.0.192"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"32.0.0.192", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);

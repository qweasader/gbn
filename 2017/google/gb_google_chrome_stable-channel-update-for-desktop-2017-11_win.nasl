# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811892");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2017-15398", "CVE-2017-15399");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-07 19:22:00 +0000 (Wed, 07 Nov 2018)");
  script_tag(name:"creation_date", value:"2017-11-07 12:15:57 +0530 (Tue, 07 Nov 2017)");
  script_name("Google Chrome Security Updates(stable-channel-update-for-desktop-2017-11)-Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A stack buffer overflow error in QUIC.

  - An use after free error in V8.");

  script_tag(name:"impact", value:"Successful exploitation of these
  vulnerabilities will allow remote attackers to corrupt valid data,
  execute arbitrary code or cause denial of service condition.");

  script_tag(name:"affected", value:"Google Chrome version
  prior to 62.0.3202.89 on Windows");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  62.0.3202.89 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2017/11/stable-channel-update-for-desktop.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"62.0.3202.89"))
{
  report = report_fixed_ver( installed_version:vers, fixed_version:"62.0.3202.89", install_path:path );
  security_message(data:report);
  exit(0);
}

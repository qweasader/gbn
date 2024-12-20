# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.816710");
  script_version("2024-06-28T05:05:33+0000");
  script_cve_id("CVE-2020-6422", "CVE-2020-6424", "CVE-2020-6425", "CVE-2020-6426",
                "CVE-2020-6427", "CVE-2020-6428", "CVE-2020-6429", "CVE-2019-20503",
                "CVE-2020-6449");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-31 17:07:00 +0000 (Thu, 31 Mar 2022)");
  script_tag(name:"creation_date", value:"2020-03-20 13:41:39 +0530 (Fri, 20 Mar 2020)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop_18-2020-03) - Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to

  - A use after free issue in WebGL.

  - A use after free in media.

  - An insufficient policy enforcement in extensions.

  - An inappropriate implementation in V8.

  - A use after free issue in audio.

  - An out of bounds read issue in usersctplib.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to
  execute arbitrary code, disclose sensitive information and cause denial of service
  condition.");

  script_tag(name:"affected", value:"Google Chrome version prior to 80.0.3987.149.");

  script_tag(name:"solution", value:"Update to Google Chrome version 80.0.3987.149
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2020/03/stable-channel-update-for-desktop_18.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"80.0.3987.149")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"80.0.3987.149", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818800");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2021-37977", "CVE-2021-37978", "CVE-2021-37979", "CVE-2021-37980");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-04 18:37:00 +0000 (Thu, 04 Nov 2021)");
  script_tag(name:"creation_date", value:"2022-11-22 12:14:49 +0530 (Tue, 22 Nov 2022)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop-2021-10) - Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to

  - Use after free in Garbage Collection.

  - Heap buffer overflow errors in Blink and WebRTC.

  - An inappropriate implementation in Sandbox.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code, cause denial of service and bypass security restrictions.");

  script_tag(name:"affected", value:"Google Chrome version prior to 94.0.4606.81
  on Windows");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version 94.0.4606.81
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2021/10/stable-channel-update-for-desktop.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"94.0.4606.81"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"94.0.4606.81", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);

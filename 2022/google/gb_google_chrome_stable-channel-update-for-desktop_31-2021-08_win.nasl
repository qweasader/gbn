# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826744");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2021-30606", "CVE-2021-30607", "CVE-2021-30608", "CVE-2021-30609",
                "CVE-2021-30610", "CVE-2021-30611", "CVE-2021-30612", "CVE-2021-30613",
                "CVE-2021-30614", "CVE-2021-30615", "CVE-2021-30616", "CVE-2021-30617",
                "CVE-2021-30618", "CVE-2021-30619", "CVE-2021-30620", "CVE-2021-30621",
                "CVE-2021-30622", "CVE-2021-30623", "CVE-2021-30624");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-07 21:58:00 +0000 (Tue, 07 Sep 2021)");
  script_tag(name:"creation_date", value:"2023-01-02 12:46:11 +0530 (Mon, 02 Jan 2023)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop_31-2021-08) - Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to

  - Multiple use after free errors.

  - A heap buffer overflow error.

  - Cross-origin data leak in Navigation.

  - An insufficient policy enforcement in Blink.

  - Policy bypass in Blink.

  - Multiple UI Spoofing errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code, conduct spoofing attack, cause denial of service and
  gain access to sensitive data.");

  script_tag(name:"affected", value:"Google Chrome version prior to 93.0.4577.63
  on Windows");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version 93.0.4577.63
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2021/08/stable-channel-update-for-desktop_31.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"93.0.4577.63"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"93.0.4577.63", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);

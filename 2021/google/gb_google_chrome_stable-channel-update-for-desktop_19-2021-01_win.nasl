# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817588");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2021-21117", "CVE-2021-21118", "CVE-2021-21119", "CVE-2021-21120",
                "CVE-2021-21121", "CVE-2021-21122", "CVE-2021-21123", "CVE-2021-21124",
                "CVE-2021-21125", "CVE-2020-16044", "CVE-2021-21126", "CVE-2021-21127",
                "CVE-2021-21128", "CVE-2021-21129", "CVE-2021-21130", "CVE-2021-21131",
                "CVE-2021-21132", "CVE-2021-21133", "CVE-2021-21134", "CVE-2021-21135",
                "CVE-2021-21136", "CVE-2021-21137", "CVE-2021-21138", "CVE-2021-21139",
                "CVE-2021-21140", "CVE-2021-21141");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-08 18:51:00 +0000 (Mon, 08 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-01-20 10:06:39 +0530 (Wed, 20 Jan 2021)");
  script_name("Google Chrome Security Updates (stable-channel-update-for-desktop_19-2021-01) - Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to

  - Insufficient policy enforcement in Cryptohome.

  - Insufficient data validation in V8.

  - Use after free in Media.

  - Use after free in WebSQL.

  - Use after free in Omnibox.

  - Use after free in Blink.

  - Insufficient data validation in File System API.

  - Potential user after free in Speech Recognizer.

  - Insufficient policy enforcement in File System API.

  - Use after free in WebRTC.

  - Insufficient policy enforcement in extensions.

  - Heap buffer overflow in Blink.

  - Inappropriate implementation in DevTools.

  - Insufficient policy enforcement in Downloads.

  - Incorrect security UI in Page Info.

  - Inappropriate implementation in Performance API.

  - Insufficient policy enforcement in WebView.

  - Use after free in DevTools.

  - Inappropriate implementation in iframe sandbox.

  - Uninitialized Use in USB.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code, gain access to sensitive data, bypass security
  restrictions, and launch denial of service attacks.");

  script_tag(name:"affected", value:"Google Chrome version
  prior to 88.0.4324.96 on Windows");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  88.0.4324.96 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2021/01/stable-channel-update-for-desktop_19.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
chr_ver = infos['version'];
chr_path = infos['location'];

if(version_is_less(version:chr_ver, test_version:"88.0.4324.96"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"88.0.4324.96", install_path:chr_path);
  security_message(data:report);
  exit(0);
}
exit(99);

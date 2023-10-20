# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818006");
  script_version("2023-10-13T16:09:03+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2021-21159", "CVE-2021-21160", "CVE-2021-21161", "CVE-2021-21162",
                "CVE-2021-21163", "CVE-2021-21164", "CVE-2021-21165", "CVE-2021-21166",
                "CVE-2021-21167", "CVE-2021-21168", "CVE-2021-21169", "CVE-2021-21170",
                "CVE-2021-21171", "CVE-2021-21172", "CVE-2021-21173", "CVE-2021-21174",
                "CVE-2021-21175", "CVE-2021-21176", "CVE-2021-21177", "CVE-2021-21178",
                "CVE-2021-21179", "CVE-2021-21180", "CVE-2020-27844", "CVE-2021-21181",
                "CVE-2021-21182", "CVE-2021-21183", "CVE-2021-21184", "CVE-2021-21185",
                "CVE-2021-21186", "CVE-2021-21187", "CVE-2021-21188", "CVE-2021-21189",
                "CVE-2021-21190");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-02-23 10:52:28 +0530 (Tue, 23 Feb 2021)");
  script_name("Google Chrome Security Updates (stable-channel-update-for-desktop-2021-03) - Mac OS X");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to

  - Heap buffer overflow in TabStrip.

  - Heap buffer overflow in WebAudio.

  - Use after free in WebRTC.

  - Insufficient data validation in Reader Mode.

  - Insufficient data validation in Chrome for iOS.

  - Object lifecycle issue in audio.

  - Use after free in bookmarks.

  - Insufficient policy enforcement in appcache.

  - Out of bounds memory access in V8.

  - Incorrect security UI in Loader.

  - Incorrect security UI in TabStrip and Navigation.

  - Insufficient policy enforcement in File System API.

  - Side-channel information leakage in Network Internals.

  - Inappropriate implementation in Referrer.

  - Inappropriate implementation in Site isolation.

  - Inappropriate implementation in full screen mode.

  - Insufficient policy enforcement in Autofill.

  - Inappropriate implementation in Compositing.

  - Use after free in Network Internals.

  - Use after free in tab search.

  - Heap buffer overflow in OpenJPEG.

  - Side-channel information leakage in autofill.

  - Insufficient policy enforcement in navigations.

  - Inappropriate implementation in performance APIs.

  - Insufficient policy enforcement in extensions.

  - Insufficient policy enforcement in QR scanning.

  - Insufficient data validation in URL formatting.

  - Use after free in Blink.

  - Insufficient policy enforcement in payments.

  - Uninitialized Use in PDFium.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to
  execute arbitrary code, disclose sensitive information and cause denial of service
  condition.");

  script_tag(name:"affected", value:"Google Chrome version
  prior to 89.0.4389.72 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  89.0.4389.72 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2021/03/stable-channel-update-for-desktop.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"89.0.4389.72"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"89.0.4389.72", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);

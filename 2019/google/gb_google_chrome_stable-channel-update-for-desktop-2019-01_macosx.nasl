# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814833");
  script_version("2023-10-13T16:09:03+0000");
  script_cve_id("CVE-2019-5754", "CVE-2019-5782", "CVE-2019-5755", "CVE-2019-5756",
                "CVE-2019-5757", "CVE-2019-5758", "CVE-2019-5759", "CVE-2019-5760",
                "CVE-2019-5761", "CVE-2019-5762", "CVE-2019-5763", "CVE-2019-5764",
                "CVE-2019-5765", "CVE-2019-5766", "CVE-2019-5767", "CVE-2019-5768",
                "CVE-2019-5769", "CVE-2019-5770", "CVE-2019-5771", "CVE-2019-5772",
                "CVE-2019-5773", "CVE-2019-5774", "CVE-2019-5775", "CVE-2019-5776",
                "CVE-2019-5777", "CVE-2019-5778", "CVE-2019-5779", "CVE-2019-5780",
                "CVE-2019-5781", "CVE-2019-5783", "CVE-2019-5785", "CVE-2018-20073");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-17 14:20:00 +0000 (Wed, 17 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-01-30 12:34:14 +0530 (Wed, 30 Jan 2019)");
  script_name("Google Chrome Security Updates (stable-channel-update-for-desktop-2019-01) - Mac OS X");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Inappropriate implementation in QUIC Networking and V8.

  - Insufficient policy enforcement in the browser, Omnibox, ServiceWorker,
    Extensions, Canvas and DevTools.

  - Insufficient validation of untrusted input in SafeBrowsing, V8, Blink and
    DevTools.

  - Use after free errors in PDFium, Blink, HTML, SwiftShader, WebRTC, FileAPI,
    Mojo interface and Payments.

  - A type confusion error in SVG.

  - Incorrect security UI in WebAPKs.

  - Heap buffer overflow errors in WebGL and SwiftShader.

  - Inappropriate implementation in downloads.

  - Stack buffer overflow issue in Skia.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to overflow the buffer, inject arbitrary code and conduct spoofing attacks.");

  script_tag(name:"affected", value:"Google Chrome version
  prior to 72.0.3626.81 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  72.0.3626.81 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2019/01/stable-channel-update-for-desktop.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"72.0.3626.81"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"72.0.3626.81", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);

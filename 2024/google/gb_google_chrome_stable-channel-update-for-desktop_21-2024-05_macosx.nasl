# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834021");
  script_version("2024-05-24T19:38:34+0000");
  script_cve_id("CVE-2024-5157", "CVE-2024-5158", "CVE-2024-5159", "CVE-2024-5160");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-05-24 19:38:34 +0000 (Fri, 24 May 2024)");
  script_tag(name:"creation_date", value:"2024-05-22 15:17:45 +0530 (Wed, 22 May 2024)");
  script_name("Google Chrome Security Update(stable-channel-update-for-desktop_21-2024-05) - Mac OS X");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-5157: Use after free in Scheduling

  - CVE-2024-5158: Type Confusion in V8

  - CVE-2024-5159: Heap buffer overflow in ANGLE

  - CVE-2024-5160: Heap buffer overflow in Dawn");

  script_tag(name: "impact" , value:"Successful exploitation allows an attacker
  to run arbitrary code and cause a denial of service attacks.");

  script_tag(name: "affected" , value:"Google Chrome prior to version
  125.0.6422.76 on Mac OS X");

  script_tag(name: "solution", value:"Update to version 125.0.6422.76/.77 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/05/stable-channel-update-for-desktop_21.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"125.0.6422.76")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"125.0.6422.76/.77", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

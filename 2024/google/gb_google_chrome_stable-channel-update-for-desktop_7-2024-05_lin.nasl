# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832970");
  script_version("2024-05-14T05:05:26+0000");
  script_cve_id("CVE-2024-4558", "CVE-2024-4559");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-05-14 05:05:26 +0000 (Tue, 14 May 2024)");
  script_tag(name:"creation_date", value:"2024-05-08 12:30:37 +0530 (Wed, 08 May 2024)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop_7-2024-05) - Linux");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-4558: Use after free error in ANGLE.

  - CVE-2024-4559: Heap buffer overflow vulnerability in WebAudio.");

  script_tag(name: "impact" , value:"Successful exploitation allows an attacker
  to potentially exploit heap corruption via a crafted HTML page.");

  script_tag(name: "affected" , value:"Google Chrome prior to version
  124.0.6367.155 on Linux");

  script_tag(name: "solution", value:"Update to version 124.0.6367.155 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/05/stable-channel-update-for-desktop_7.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"124.0.6367.155")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"124.0.6367.155", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

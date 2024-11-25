# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834746");
  script_version("2024-11-15T05:05:36+0000");
  script_cve_id("CVE-2024-11110", "CVE-2024-11111", "CVE-2024-11112", "CVE-2024-11113",
                "CVE-2024-11114", "CVE-2024-11115", "CVE-2024-11116", "CVE-2024-11117");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-11-15 05:05:36 +0000 (Fri, 15 Nov 2024)");
  script_tag(name:"creation_date", value:"2024-11-13 21:29:44 +0530 (Wed, 13 Nov 2024)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop_12-2024-11) - Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-11110: Inappropriate implementation in Blink

  - CVE-2024-11113: Use after free in Accessibility");

  script_tag(name: "impact" , value:"Successful exploitation allows an attacker
  to run arbitrary code, bypass security restrictions, conduct spoofing
  and denial of service attacks.");

  script_tag(name: "affected" , value:"Google Chrome version prior to
  131.0.6778.69 on Windows");

  script_tag(name: "solution", value:"Update to version 131.0.6778.69/.70 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/11/stable-channel-update-for-desktop_12.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"131.0.6778.69")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"131.0.6778.69/.70", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

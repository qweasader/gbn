# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832719");
  script_version("2024-02-09T05:06:25+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-6348", "CVE-2023-6347", "CVE-2023-6346", "CVE-2023-6350",
                "CVE-2023-6351", "CVE-2023-6345");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-01 20:18:00 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-11-29 14:34:08 +0530 (Wed, 29 Nov 2023)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop_28-2023-11) - Linux");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Type Confusion in Spellcheck.

  - Use after free in Mojo.

  - Use after free in WebAudio.

  - Out of bounds memory access in libavif.

  - Use after free in libavif.

  - Integer overflow in Skia.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to run arbitrary code and cause a denial of service on an affected system.");

  script_tag(name:"affected", value:"Google Chrome version prior to
  119.0.6045.199 on Linux");

  script_tag(name:"solution", value:"Upgrade to version 119.0.6045.199 or
  later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2023/11/stable-channel-update-for-desktop_28.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"119.0.6045.199")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"119.0.6045.199", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832815");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2024-1284", "CVE-2024-1283");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-14 18:19:17 +0000 (Wed, 14 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-02-07 11:37:36 +0530 (Wed, 07 Feb 2024)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop-2024-02) - Linux");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Use after free in Mojo.

  - Heap buffer overflow in Skia.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to potentially exploit heap corruption via a crafted HTML page to
  cause a memory leak on an affected system.");

  script_tag(name:"affected", value:"Google Chrome version prior to
  121.0.6167.160 on Linux");

  script_tag(name:"solution", value:"Upgrade to version 121.0.6167.160 or
  later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/02/stable-channel-update-for-desktop.html");
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

if(version_is_less(version:vers, test_version:"121.0.6167.160")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"121.0.6167.160", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

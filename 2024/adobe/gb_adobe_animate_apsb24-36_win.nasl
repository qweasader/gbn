# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:animate";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833921");
  script_version("2024-07-11T05:05:33+0000");
  script_cve_id("CVE-2024-30282", "CVE-2024-30293", "CVE-2024-30294", "CVE-2024-30298",
                "CVE-2024-30295", "CVE-2024-30296", "CVE-2024-30297");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-07-11 05:05:33 +0000 (Thu, 11 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-05-16 09:15:12 +0000 (Thu, 16 May 2024)");
  script_tag(name:"creation_date", value:"2024-05-16 14:55:25 +0530 (Thu, 16 May 2024)");
  script_name("Adobe Animate Multiple Vulnerabilities (APSB24-36) - Windows");

  script_tag(name:"summary", value:"Adobe Animate is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-30298: out-of-bounds read error

  - CVE-2024-30282: out-of-bounds write error

  Please see the references for more information on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to execute arbitrary code, cause memory leak and denial of service.");

  script_tag(name:"affected", value:"Adobe Animate 2023 version 23.0.5 and
  prior and 2024 version 24.0.2 and earlier versions on Windows.");

  script_tag(name:"solution", value:"Update Adobe Animate 2023 to version
  23.0.6 or later, Adobe Animate 2024 to version 24.0.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/animate/apsb24-36.html");
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_adobe_animate_detect_win.nasl");
  script_mandatory_keys("Adobe/Animate/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"23.0", test_version2:"23.0.5") ||
   version_in_range(version:vers, test_version:"24.0", test_version2:"24.0.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"23.0.6, 24.0.3 or later", install_path:path);
  security_message(port:0, data: report);
  exit(0);
}

exit(99);

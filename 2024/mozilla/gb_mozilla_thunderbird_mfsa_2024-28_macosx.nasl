# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834070");
  script_version("2024-08-19T05:05:38+0000");
  script_cve_id("CVE-2024-5702", "CVE-2024-5688", "CVE-2024-5690", "CVE-2024-5691",
                "CVE-2024-5693", "CVE-2024-5696", "CVE-2024-5700");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-08-19 05:05:38 +0000 (Mon, 19 Aug 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-16 14:44:05 +0000 (Fri, 16 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-06-17 14:43:46 +0530 (Mon, 17 Jun 2024)");
  script_name("Mozilla Thunderbird Security Update (mfsa_2024-28) - Mac OS X");

  script_tag(name: "summary" , value:"Mozilla Thunderbird is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-5688: Use-after-free in JavaScript object transplant.

  - CVE-2024-5693: Cross-Origin Image leak via Offscreen Canvas.

  Please see the references for more information on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to run arbitrary code, bypass security restrictions, disclose information and
  cause denial of service attacks.");

  script_tag(name: "affected" , value:"Mozilla Thunderbird prior to version
  115.12.");

  script_tag(name: "solution" , value:"Update to version 115.12 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-28/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Thunderbird/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"115.12")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"115.12", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

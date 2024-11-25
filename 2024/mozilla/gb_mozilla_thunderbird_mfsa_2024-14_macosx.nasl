# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832887");
  script_version("2024-04-05T05:05:37+0000");
  script_cve_id("CVE-2024-0743", "CVE-2024-2614", "CVE-2024-2608", "CVE-2024-2616",
                "CVE-2023-5388", "CVE-2024-2610", "CVE-2024-2611", "CVE-2024-2612");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-04-05 05:05:37 +0000 (Fri, 05 Apr 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-29 22:47:27 +0000 (Mon, 29 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-03-25 14:35:59 +0530 (Mon, 25 Mar 2024)");
  script_name("Mozilla Thunderbird Security Update (mfsa_2024-14) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-0743: Crash in NSS TLS method

  - CVE-2024-2610: Improper handling of html and body tags enabled CSP nonce leakage

  Please see the references for more information on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to obtain sensitive information and conduct arbitrary code execution.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before
  115.9 on Mac OS X.");

  script_tag(name:"solution", value:"Update to version 115.9 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-14/");
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

if(version_is_less(version:vers, test_version:"115.9")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"115.9", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

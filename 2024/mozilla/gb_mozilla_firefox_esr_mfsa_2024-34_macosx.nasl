# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834293");
  script_version("2024-09-05T15:07:28+0000");
  script_cve_id("CVE-2024-7519", "CVE-2024-7521", "CVE-2024-7522", "CVE-2024-7524",
                "CVE-2024-7525", "CVE-2024-7526", "CVE-2024-7527", "CVE-2024-7529",
                "CVE-2024-7531");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-09-05 15:07:28 +0000 (Thu, 05 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-12 16:04:20 +0000 (Mon, 12 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-08-08 10:05:42 +0530 (Thu, 08 Aug 2024)");
  script_name("Mozilla Firefox ESR Security Update (mfsa_2024-34) - Mac OS X");

  script_tag(name:"summary", value:"Firefox ESR is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-7519: Out of bounds memory access error in graphics shared memory handling.

  - CVE-2024-7522: Out of bounds read error in editor component.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to run arbitrary code, disclose information, bypass security restrictions and
  cause denial of service attacks.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR prior to version
  115.14 and 128.x prior to 128.1 on Mac OS X.");

  script_tag(name:"solution", value:"Update to version 115.14 or 128.1 later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-34/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox-ESR/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"115.14")) {
  fix = "115.14 or later";
}
else if(version_in_range_exclusive(version: vers, test_version_lo: "128", test_version_up: "128.1")) {
  fix = "128.1 or later";
}

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

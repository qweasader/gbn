# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826597");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2022-42927", "CVE-2022-42928", "CVE-2022-42929", "CVE-2022-42930",
                "CVE-2022-42931", "CVE-2022-42932", "CVE-2022-46881", "CVE-2022-46885",
                "CVE-2022-46884");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-04 16:52:00 +0000 (Wed, 04 Jan 2023)");
  script_tag(name:"creation_date", value:"2022-10-19 17:19:22 +0530 (Wed, 19 Oct 2022)");
  script_name("Mozilla Firefox Security Advisory (MFSA2022-44) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Same-origin policy violation could have leaked cross-origin URLs.

  - Memory Corruption in JS Engine.

  - Denial of Service via window.print.

  - Race condition in DOM Workers.

  - Username saved to a plaintext file on disk.

  - Memory safety bugs.

  - Memory corruption in WebGL.

  - Potential use-after-free in SVG Images.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, cause denial of service and disclose
  sensitive information on an affected system.");

  script_tag(name:"affected", value:"Mozilla Firefox version before
  106 on Windows.");

  script_tag(name:"solution", value:"Update to version 106 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-44");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"106")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"106", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);

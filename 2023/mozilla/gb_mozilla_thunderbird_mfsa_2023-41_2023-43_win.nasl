# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832533");
  script_version("2023-10-13T05:06:10+0000");
  script_cve_id("CVE-2023-5168", "CVE-2023-5169", "CVE-2023-5171", "CVE-2023-5174",
                "CVE-2023-5176");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-13 05:06:10 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-29 15:17:00 +0000 (Fri, 29 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-09-27 16:30:04 +0530 (Wed, 27 Sep 2023)");
  script_name("Mozilla Thunderbird Security Update (mfsa_2023-41_2023-43) - Windows");

  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Out-of-bounds write in FilterNodeD2D1.

  - Out-of-bounds write in PathOps.

  - Use-after-free in Ion Compiler.

  - Memory Corruption in Ion Hints.

  - Double-free in process spawning on Windows.

  - Memory safety bugs fixed in Firefox 118, Firefox ESR 115.3, and Thunderbird 115.3");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to execute arbitrary code on an affected system.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before
  115.3 on Windows.");

  script_tag(name:"solution", value:"Upgrade to version 115.3
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-43/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_win.nasl");
  script_mandatory_keys("Thunderbird/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"115.3")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"115.3", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
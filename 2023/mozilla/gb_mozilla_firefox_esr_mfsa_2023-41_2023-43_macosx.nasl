# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832531");
  script_version("2023-10-13T16:09:03+0000");
  script_cve_id("CVE-2023-5169", "CVE-2023-5171", "CVE-2023-5176");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-29 15:17:00 +0000 (Fri, 29 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-09-27 16:29:46 +0530 (Wed, 27 Sep 2023)");
  script_name("Mozilla Firefox ESR Security Update (mfsa_2023-41_2023-43) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Out-of-bounds write in PathOps.

  - Use-after-free in Ion Compiler.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to execute arbitrary code on an affected system.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version before
  115.3 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to version 115.3
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-42/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox-ESR/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"115.3")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"115.3", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

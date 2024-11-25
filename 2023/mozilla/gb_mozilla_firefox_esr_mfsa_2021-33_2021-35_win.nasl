# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826761");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2021-29988", "CVE-2021-29984", "CVE-2021-29980", "CVE-2021-29985",
                "CVE-2021-29989");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-25 15:33:00 +0000 (Wed, 25 Aug 2021)");
  script_tag(name:"creation_date", value:"2023-01-10 17:30:37 +0530 (Tue, 10 Jan 2023)");
  script_name("Mozilla Firefox ESR Security Advisories (MFSA2021-33, MFSA2021-35) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Memory corruption as a result of incorrect style treatment.

  - Incorrect instruction reordering during JIT optimization.

  - Uninitialized memory in a canvas object could have led to memory corruption.

  - Use-after-free media channels.

  - Memory safety bugs fixed.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to execute arbitrary code and cause denial of service on an affected
  system.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version before
  78.13 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR version 78.13
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-34/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_mandatory_keys("Firefox-ESR/Win/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE) ) exit( 0 );
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"78.13"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"78.13", install_path:path);
  security_message(data:report);
  exit(0);
}

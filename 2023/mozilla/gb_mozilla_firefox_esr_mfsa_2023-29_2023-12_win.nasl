# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832513");
  script_version("2023-10-13T05:06:10+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-4863");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-13 05:06:10 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-18 17:48:00 +0000 (Mon, 18 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-09-14 14:26:54 +0530 (Thu, 14 Sep 2023)");
  script_name("Mozilla Firefox ESR Security Update (mfsa_2023-29_2023-12) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to heap buffer
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to heap buffer
  overflow in WebP");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to conduct heap buffer overflow attack on an affected system.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version before
  102.15.1 and 115.x prior to 115.2.1 on Windows.");

  script_tag(name:"solution", value:"Upgrade to version 102.15.1 or 115.2.1
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-40/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_mandatory_keys("Firefox-ESR/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"102.15.1")) {
  fix = "102.15.1";
}
else if(vers =~ "^115\." && version_is_less(version:vers, test_version:"115.2.1")) {
  fix = "115.2.1";
}

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

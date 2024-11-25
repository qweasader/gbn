# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817543");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2020-26970");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-10 18:52:00 +0000 (Thu, 10 Dec 2020)");
  script_tag(name:"creation_date", value:"2021-01-29 08:41:15 +0530 (Fri, 29 Jan 2021)");
  script_name("Mozilla Thunderbird Security Advisories (MFSA2020-53, MFSA2020-53) - Windows");

  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to:
  Stack overflow due to incorrect parsing of SMTP server response codes.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to corrupt stack that may be exploitable.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before
  78.5.1 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 78.5.1
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-53/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_win.nasl");
  script_mandatory_keys("Thunderbird/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
tbVer = infos['version'];
tbPath = infos['location'];

if(version_is_less(version:tbVer, test_version:"78.5.1"))
{
  report = report_fixed_ver(installed_version:tbVer, fixed_version:"78.5.1", install_path:tbPath);
  security_message(data:report);
  exit(0);
}

# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818512");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2021-38492");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-04 20:51:00 +0000 (Thu, 04 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-09-09 00:46:50 +0530 (Thu, 09 Sep 2021)");
  script_name("Mozilla Firefox ESR Security Advisories (MFSA2021-34, MFSA2021-40) - Windows");

  script_tag(name:"summary", value:"This host is missing a security update
  according to Mozilla.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw is due to,

  - Navigating to 'mk:' URL scheme could load Internet Explorer.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code on victim's system.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version before
  78.14 and before 91.1 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR version 78.14 or
  91.1 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-40/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_mandatory_keys("Firefox-ESR/Win/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"78.14") ||
   version_in_range(version:vers, test_version:"91.0", test_version2:"91.0.2"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"Upgrade to 78.14 or 91.1 or later", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);

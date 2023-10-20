# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815221");
  script_version("2023-10-13T16:09:03+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2019-11707");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-31 14:15:00 +0000 (Tue, 31 Jan 2023)");
  script_tag(name:"creation_date", value:"2019-06-19 10:43:28 +0530 (Wed, 19 Jun 2019)");
  script_name("Mozilla Firefox Security Update (mfsa_2019-17_2019-18) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to a type confusion vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a type confusion error
  in Array.pop");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers
  to crash the application and launch further attacks.");

  script_tag(name:"affected", value:"Mozilla Firefox version before 67.0.3
  on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 67.0.3
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-18/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"67.0.3")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"67.0.3", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);

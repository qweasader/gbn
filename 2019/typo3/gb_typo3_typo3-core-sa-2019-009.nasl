# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:typo3:typo3";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142395");
  script_version("2023-04-05T10:19:45+0000");
  script_tag(name:"last_modification", value:"2023-04-05 10:19:45 +0000 (Wed, 05 Apr 2023)");
  script_tag(name:"creation_date", value:"2019-05-10 09:08:25 +0000 (Fri, 10 May 2019)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("TYPO3 Multiple Information Disclosure Vulnerabilities (TYPO3-CORE-SA-2019-009, TYPO3-CORE-SA-2019-010)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_typo3_http_detect.nasl");
  script_mandatory_keys("typo3/detected");

  script_tag(name:"summary", value:"TYPO3 is prone to multiple information disclosure vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"TYPO3 is prone to multiple information disclosure vulnerabilities:

  - Information Disclosure in Page Tree

  - Information Disclosure in User Authentication");

  script_tag(name:"affected", value:"TYPO3 versions 9.0.0-9.5.5.");

  script_tag(name:"solution", value:"Update to version 9.5.6 or later.");

  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2019-009/");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2019-010/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE, version_regex: "[0-9]+\.[0-9]+\.[0-9]+")) # nb: Version might not be exact enough
  exit(0);

version = infos['version'];
path = infos['location'];

if (version_in_range(version: version, test_version: "9.0.0", test_version2: "9.5.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.5.6", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

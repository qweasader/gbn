# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:typo3:typo3";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146338");
  script_version("2023-04-05T10:19:45+0000");
  script_tag(name:"last_modification", value:"2023-04-05 10:19:45 +0000 (Wed, 05 Apr 2023)");
  script_tag(name:"creation_date", value:"2021-07-21 05:01:30 +0000 (Wed, 21 Jul 2021)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-29 17:39:00 +0000 (Thu, 29 Jul 2021)");

  script_cve_id("CVE-2021-32668", "CVE-2021-32669");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("TYPO3 Multiple XSS Vulnerabilities (TYPO3-CORE-SA-2021-010, TYPO3-CORE-SA-2021-011)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_typo3_http_detect.nasl");
  script_mandatory_keys("typo3/detected");

  script_tag(name:"summary", value:"TYPO3 is prone to multiple cross-site scripting (XSS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-32668: Cross-Site Scripting in Query Generator & Query View

  - CVE-2021-32669: Cross-Site Scripting in Backend Grid View");

  script_tag(name:"affected", value:"TYPO3 version 8.0.0 through 8.7.40 ELTS, 9.0.0 through 9.5.27,
  10.0.0 through 10.4.17 and 11.0.0 through 11.3.0.");

  script_tag(name:"solution", value:"Update to version 8.7.41 ELTS, 9.5.28, 10.4.18, 11.3.1 or later.");

  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2021-010");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2021-011");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE, version_regex: "[0-9]+\.[0-9]+\.[0-9]+")) # nb: Version might not be exact enough
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "8.0.0", test_version2: "8.7.40")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.7.41 ELTS", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.0.0", test_version2: "9.5.27")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.5.28", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.0.0", test_version2: "10.4.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.4.18", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "11.0.0", test_version2: "11.3.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.3.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

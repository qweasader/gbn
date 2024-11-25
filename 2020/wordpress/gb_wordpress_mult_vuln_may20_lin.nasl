# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143816");
  script_version("2024-02-08T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-02-08 05:05:59 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2020-05-05 06:59:10 +0000 (Tue, 05 May 2020)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-18 15:05:00 +0000 (Tue, 18 Aug 2020)");

  script_cve_id("CVE-2020-11026", "CVE-2020-11027", "CVE-2020-11028", "CVE-2020-11029");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Multiple Vulnerabilities (May 2020) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("wordpress/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"WordPress is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"WordPress is prone to multiple vulnerabilities:

  - Specially crafted filenames in WordPress leading to XSS (CVE-2020-11026)

  - Password reset links invalidation issue (CVE-2020-11027)

  - Unauthenticated disclosure of certain private posts (CVE-2020-11028)

  - Cross-site scripting in stats method (object cache) (CVE-2020-11029)");

  script_tag(name:"affected", value:"WordPress versions 3.7 - 5.4.");

  script_tag(name:"solution", value:"Update to version 3.7.33, 3.8.33, 3.9.31, 4.0.30, 4.1.30, 4.2.27, 4.3.23,
  4.4.22, 4.5.21, 4.6.18, 4.7.17, 4.8.13, 4.9.14, 5.0.9, 5.1.5, 5.2.6, 5.3.3, 5.4.1 or later.");

  script_xref(name:"URL", value:"https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-3gw2-4656-pfr2");
  script_xref(name:"URL", value:"https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-ww7v-jg8c-q6jw");
  script_xref(name:"URL", value:"https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-xhx9-759f-6p2w");
  script_xref(name:"URL", value:"https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-568w-8m88-8g2c");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "3.7", test_version2: "3.7.32")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.7.33", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.8", test_version2: "3.8.32")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.8.33", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.9", test_version2: "3.9.30")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.31", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.0", test_version2: "4.0.29")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.30", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.1", test_version2: "4.1.29")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.30", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.2", test_version2: "4.2.26")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.27", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.3", test_version2: "4.3.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.23", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.4", test_version2: "4.4.21")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.22", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.5", test_version2: "4.5.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.5.21", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.6", test_version2: "4.6.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.6.18", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.7", test_version2: "4.7.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.7.17", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.8", test_version2: "4.8.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.8.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.9", test_version2: "4.9.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.9.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.0", test_version2: "5.0.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.1", test_version2: "5.1.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.2", test_version2: "5.2.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.3", test_version2: "5.3.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "5.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

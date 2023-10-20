# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149761");
  script_version("2023-10-13T05:06:10+0000");
  script_tag(name:"last_modification", value:"2023-10-13 05:06:10 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-06-09 02:15:54 +0000 (Fri, 09 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-01 16:38:00 +0000 (Tue, 01 Aug 2023)");

  script_cve_id("CVE-2023-3247");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 8.0.29, 8.1.x < 8.1.20, 8.2.x < 8.2.7 Security Update - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PHP is prone to a missing error check and insufficient random
  bytes in HTTP Digest authentication for SOAP vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"PHP prior to version 8.0.29, 8.1.x prior to 8.1.20 and 8.2.x
  prior to 8.2.7.");

  script_tag(name:"solution", value:"Update to version 8.0.29, 8.1.10, 8.2.7 or later.");

  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.0.29");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.1.20");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.2.7");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-76gg-c692-v2mw");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "8.0.29")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.29", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.1", test_version_up: "8.1.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.1.20", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.2", test_version_up: "8.2.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.2.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

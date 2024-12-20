# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mariadb:mariadb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149186");
  script_version("2023-12-01T05:05:39+0000");
  script_tag(name:"last_modification", value:"2023-12-01 05:05:39 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-01-23 06:45:09 +0000 (Mon, 23 Jan 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-23 19:24:00 +0000 (Thu, 23 Feb 2023)");

  script_cve_id("CVE-2022-47015");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MariaDB DoS Vulnerability (MDEV-29644) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("MariaDB/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"MariaDB is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"It is possible for function spider_db_mbase::print_warnings to
  dereference a null pointer.");

  script_tag(name:"affected", value:"MariaDB versions prior to 10.3.39, 10.4.x prior to 10.4.29,
  10.5.x prior to 10.5.20, 10.6.x prior to 10.6.13, starting from 10.7.0 and prior to 10.8.8,
  10.9.x prior to 10.9.6, 10.10.x prior to 10.10.4 and 10.11.x prior to 10.11.3.");

  script_tag(name:"solution", value:"Update to version 10.3.39, 10.4.29, 10.5.20, 10.6.13, 10.8.8,
  10.9.6, 10.10.4, 10.11.3 or later.");

  script_xref(name:"URL", value:"https://github.com/MariaDB/server/commit/be0a46b3d52b58956fd0d47d040b9f4514406954");
  script_xref(name:"URL", value:"https://jira.mariadb.org/browse/MDEV-29644");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/security/#full-list-of-cves-fixed-in-mariadb");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "10.3.39")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.3.39");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.4.0", test_version_up: "10.4.29")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.4.29");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.5.0", test_version_up: "10.5.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.5.20");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.6.0", test_version_up: "10.6.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.6.13");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.7.0", test_version_up: "10.8.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.8.8");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.9.0", test_version_up: "10.9.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.9.6");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.10.0", test_version_up: "10.10.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.10.4");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.11.0", test_version_up: "10.11.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.11.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

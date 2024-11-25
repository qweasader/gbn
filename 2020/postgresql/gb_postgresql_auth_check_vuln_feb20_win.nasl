# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:postgresql:postgresql";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143611");
  script_version("2024-07-19T05:05:32+0000");
  script_tag(name:"last_modification", value:"2024-07-19 05:05:32 +0000 (Fri, 19 Jul 2024)");
  script_tag(name:"creation_date", value:"2020-03-19 03:48:57 +0000 (Thu, 19 Mar 2020)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-15 13:28:00 +0000 (Thu, 15 Oct 2020)");

  script_cve_id("CVE-2020-1720");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PostgreSQL < 9.4.26, 9.5.x < 9.5.21, 9.6.x < 9.6.17, 10.x < 10.12, 11.x < 11.7, 12.x < 12.2 Authorization Check Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_postgresql_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("postgresql/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PostgreSQL is prone to an authorization check vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"The ALTER ... DEPENDS ON EXTENSION sub-commands do not perform authorization
  checks, which can allow an unprivileged user to drop any function, procedure, materialized view, index, or
  trigger under certain conditions. This attack is possible if an administrator has installed an extension and an
  unprivileged user can CREATE, or an extension owner either executes DROP EXTENSION predictably or can be
  convinced to execute DROP EXTENSION.");

  script_tag(name:"affected", value:"PostgreSQL versions prior to 9.4.26, 9.5.x prior to 9.5.21, 9.6.x prior to
  9.6.17, 10.x prior to 10.12, 11.x prior to 11.7 and 12.x prior to 12.2.");

  script_tag(name:"solution", value:"Update to version 9.4.26, 9.5.21, 9.6.17, 10.12, 11.7, 12.2 or later.");

  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/2011/");

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

if (version_is_less(version: version, test_version: "9.4.26")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.4.26", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.5.0", test_version2: "9.5.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.5.21", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.6.0", test_version2: "9.6.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.6.17", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.0", test_version2: "10.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "11.0", test_version2: "11.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "12.0", test_version2: "12.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

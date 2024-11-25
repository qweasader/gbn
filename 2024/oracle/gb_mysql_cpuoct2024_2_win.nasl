# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:mysql";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170869");
  script_version("2024-10-18T15:39:59+0000");
  script_tag(name:"last_modification", value:"2024-10-18 15:39:59 +0000 (Fri, 18 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-10-16 15:00:50 +0000 (Wed, 16 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-15 20:15:09 +0000 (Tue, 15 Oct 2024)");

  script_cve_id("CVE-2024-21207");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle MySQL Server <= 8.0.38, 8.1 <= 8.4.1, 9.0 <= 9.0.1 Security Update (cpuoct2024) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("oracle/mysql/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Oracle MySQL Server is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Oracle MySQL Server version 8.0.38 and prior, 8.1 through
  8.4.1 and 9.0 through 9.0.1.");

  script_tag(name:"solution", value:"Update to version 8.0.39, 8.4.2, 9.0.2 or later.");

  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpuoct2024.html#AppendixMSQL");
  script_xref(name:"Advisory-ID", value:"cpuoct2024");

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

if (version_is_less_equal(version: version, test_version: "8.0.38")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.39", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.1", test_version2: "8.4.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.4.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.0", test_version2: "9.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

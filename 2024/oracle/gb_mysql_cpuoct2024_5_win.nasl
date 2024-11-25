# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:mysql";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170877");
  script_version("2024-10-18T15:39:59+0000");
  script_tag(name:"last_modification", value:"2024-10-18 15:39:59 +0000 (Fri, 18 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-10-16 15:00:50 +0000 (Wed, 16 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-12 17:30:51 +0000 (Mon, 12 Aug 2024)");

  # nb: From the linked advisory: The patch for CVE-2024-5535 also addresses CVE-2024-6119
  script_cve_id("CVE-2024-5535", "CVE-2024-6119", "CVE-2024-21230", "CVE-2024-7264",
                "CVE-2024-21196", "CVE-2024-21194", "CVE-2024-21199", "CVE-2024-21218",
                "CVE-2024-21236", "CVE-2024-21239", "CVE-2024-21198", "CVE-2024-21219",
                "CVE-2024-21203", "CVE-2024-21197", "CVE-2024-21201", "CVE-2024-21241",
                "CVE-2024-21193", "CVE-2024-21213", "CVE-2024-21231", "CVE-2024-21237");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle MySQL Server <= 8.0.39, 8.1 <= 8.4.2, 9.0 <= 9.0.1 Security Update (cpuoct2024) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("oracle/mysql/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Oracle MySQL Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Oracle MySQL Server version 8.0.39 and prior, 8.1 through
  8.4.2 and 9.0 through 9.0.1.");

  script_tag(name:"solution", value:"Update to version 8.0.40, 8.4.3, 9.0.2 or later.");

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

if (version_is_less_equal(version: version, test_version: "8.0.39")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.40", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.1", test_version2: "8.4.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.4.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.0", test_version2: "9.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

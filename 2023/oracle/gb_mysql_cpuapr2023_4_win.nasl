# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:mysql";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149538");
  script_version("2023-04-19T10:19:33+0000");
  script_tag(name:"last_modification", value:"2023-04-19 10:19:33 +0000 (Wed, 19 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-19 05:18:07 +0000 (Wed, 19 Apr 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2023-0215", "CVE-2022-43551", "CVE-2023-21980", "CVE-2022-4304",
                "CVE-2022-4450", "CVE-2023-0286");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle MySQL Server <= 5.7.41, 8.x <= 8.0.32 Security Update (cpuapr2023) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("oracle/mysql/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Oracle MySQL Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Oracle MySQL Server version 5.7.41 and prior and 8.x through
  8.0.32.");

  script_tag(name:"solution", value:"Update to version 5.7.42, 8.0.33 or later.");

  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpuapr2023.html#AppendixMSQL");
  script_xref(name:"Advisory-ID", value:"cpuapr2023");

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

if (version_is_less_equal(version: version, test_version: "5.7.41")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.7.42", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.0", test_version2: "8.0.32")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.33", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

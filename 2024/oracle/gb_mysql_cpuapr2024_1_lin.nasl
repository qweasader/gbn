# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:mysql";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170754");
  script_version("2024-04-19T15:38:40+0000");
  script_tag(name:"last_modification", value:"2024-04-19 15:38:40 +0000 (Fri, 19 Apr 2024)");
  script_tag(name:"creation_date", value:"2024-04-18 11:00:44 +0000 (Thu, 18 Apr 2024)");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-23 21:32:01 +0000 (Tue, 23 Jan 2024)");

  script_cve_id("CVE-2023-6129", "CVE-2024-20994", "CVE-2024-21047", "CVE-2024-21069",
                "CVE-2024-21060", "CVE-2024-21087", "CVE-2024-20998", "CVE-2024-21009",
                "CVE-2024-21054", "CVE-2024-21062", "CVE-2024-21102", "CVE-2024-21096",
                "CVE-2024-21008", "CVE-2024-21013", "CVE-2024-21000", "CVE-2023-5678",
                "CVE-2024-0727");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle MySQL Server 8.x <= 8.0.36, 8.1.x <= 8.3.0 Security Update (cpuapr2024) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("oracle/mysql/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Oracle MySQL Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Oracle MySQL Server version 8.x through 8.0.36 and version
  8.1.x through 8.3.0.");

  script_tag(name:"solution", value:"Update to version 8.0.37, 8.3.1 or later.");

  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpuapr2024.html#AppendixMSQL");
  script_xref(name:"Advisory-ID", value:"cpuapr2024");

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

if (version_in_range(version: version, test_version: "8.0", test_version2: "8.0.36")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.37", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.1", test_version2: "8.3.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.3.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

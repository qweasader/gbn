# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:mysql";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.152679");
  script_version("2024-07-18T05:05:48+0000");
  script_tag(name:"last_modification", value:"2024-07-18 05:05:48 +0000 (Thu, 18 Jul 2024)");
  script_tag(name:"creation_date", value:"2024-07-17 05:05:06 +0000 (Wed, 17 Jul 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 23:15:21 +0000 (Tue, 16 Jul 2024)");

  script_cve_id("CVE-2024-21171", "CVE-2024-21177", "CVE-2024-21163", "CVE-2024-20996",
                "CVE-2024-21173", "CVE-2024-21179", "CVE-2024-21127", "CVE-2024-21129",
                "CVE-2024-21125", "CVE-2024-21130", "CVE-2024-21162", "CVE-2024-21142",
                "CVE-2024-21134");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle MySQL Server 8.x <= 8.0.37, 8.1.x <= 8.4.0 Security Update (cpujul2024) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("oracle/mysql/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Oracle MySQL Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Oracle MySQL Server version 8.x through 8.0.37 and 8.1.x
  through 8.4.0.");

  script_tag(name:"solution", value:"Update to version 8.0.38, 8.4.1 or later.");

  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpujul2024.html#AppendixMSQL");
  script_xref(name:"Advisory-ID", value:"cpujul2024");

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

if (version_in_range(version: version, test_version: "8.0", test_version2: "8.0.37")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.38", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.1", test_version2: "8.4.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.4.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

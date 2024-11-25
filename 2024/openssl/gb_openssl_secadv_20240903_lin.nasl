# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153009");
  script_version("2024-09-05T05:05:57+0000");
  script_tag(name:"last_modification", value:"2024-09-05 05:05:57 +0000 (Thu, 05 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-09-04 03:33:20 +0000 (Wed, 04 Sep 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2024-6119");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSSL DoS Vulnerability (20240903) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"OpenSSL is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Applications performing certificate name checks (e.g., TLS
  clients checking server certificates) may attempt to read an invalid memory address resulting in
  abnormal termination of the application process.");

  script_tag(name:"impact", value:"Abnormal termination of an application can a cause a denial of
  service.");

  script_tag(name:"affected", value:"OpenSSL versions 3.0, 3.1, 3.2 and 3.3.");

  script_tag(name:"solution", value:"Update to version 3.0.15, 3.1.7, 3.2.3, 3.3.2 or later.");

  script_xref(name:"URL", value:"https://openssl-library.org/news/secadv/20240903.txt");
  script_xref(name:"URL", value:"https://openssl-library.org/news/vulnerabilities/index.html");

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

if (version_in_range_exclusive(version: version, test_version_lo: "3.0", test_version_up: "3.0.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.1", test_version_up: "3.1.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.2", test_version_up: "3.2.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.3", test_version_up: "3.3.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.3.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

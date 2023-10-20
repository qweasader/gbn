# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104479");
  script_version("2023-10-19T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-10-19 05:05:21 +0000 (Thu, 19 Oct 2023)");
  script_tag(name:"creation_date", value:"2022-12-19 09:05:07 +0000 (Mon, 19 Dec 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-09 21:17:00 +0000 (Wed, 09 Nov 2022)");

  script_cve_id("CVE-2022-45061");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python DoS Vulnerability (Oct 2022) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Python is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An unnecessary quadratic algorithm exists in one path when
  processing some inputs to the IDNA (RFC 3490) decoder, such that a crafted, unreasonably long name
  being presented to the decoder could lead to a CPU denial of service. Hostnames are often supplied
  by remote servers that could be controlled by a malicious actor. In such a scenario, they could
  trigger excessive CPU consumption on the client attempting to make use of an attacker-supplied
  supposed hostname. For example, the attack payload could be placed in the Location header of an
  HTTP response with status code 302.");

  script_tag(name:"affected", value:"Python prior to version 3.7.16, versions 3.8.x prior to 3.8.16,
  3.9.x prior to 3.9.16, 3.10.x prior to 3.10.9 and version 3.11.0.");

  script_tag(name:"solution", value:"Update to version 3.7.16, 3.8.16, 3.9.16, 3.10.9, 3.11.1 or
  later.");

  script_xref(name:"URL", value:"https://python-security.readthedocs.io/vuln/slow-idna-large-strings.html");
  script_xref(name:"URL", value:"https://github.com/python/cpython/issues/98433");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE, version_regex:"^[0-9]+\.[0-9]+\.[0-9]+"))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "3.7.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.7.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.8.0", test_version_up: "3.8.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.8.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.9.0", test_version_up: "3.9.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.10.0", test_version_up: "3.10.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.10.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "3.11.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.11.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148942");
  script_version("2023-10-19T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-10-19 05:05:21 +0000 (Thu, 19 Oct 2023)");
  script_tag(name:"creation_date", value:"2022-11-22 14:27:15 +0000 (Tue, 22 Nov 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-25 15:23:00 +0000 (Tue, 25 Oct 2022)");

  script_cve_id("CVE-2022-37454");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python <= 3.10.x Buffer Overflow Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Python is prone to a buffer overflow vulnerability in the _sha3
  module.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Keccak XKCP SHA-3 reference implementation has an integer
  overflow and resultant buffer overflow that allows attackers to execute arbitrary code or
  eliminate expected cryptographic properties. This occurs in the sponge function interface.");

  script_tag(name:"affected", value:"Python prior to version 3.7.16, version 3.8.x through 3.8.15,
  3.9.x through 3.9.15 and 3.10.x through 3.10.8.");

  script_tag(name:"solution", value:"Update to version 3.7.16, 3.8.16, 3.9.16, 3.10.9 or later.");

  script_xref(name:"URL", value:"https://python-security.readthedocs.io/vuln/sha3-buffer-overflow.html");
  script_xref(name:"URL", value:"https://github.com/python/cpython/issues/98517");

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

if (version_is_less_equal(version: version, test_version: "3.7.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.7.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.8", test_version2: "3.8.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.8.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.9", test_version2: "3.9.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.10", test_version2: "3.10.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.10.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148870");
  script_version("2023-10-19T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-10-19 05:05:21 +0000 (Thu, 19 Oct 2023)");
  script_tag(name:"creation_date", value:"2022-11-08 07:47:16 +0000 (Tue, 08 Nov 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-08 15:03:00 +0000 (Tue, 08 Nov 2022)");

  script_cve_id("CVE-2022-42919");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python Privilege Escalation Vulnerability (Sep 2022) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Python is prone to a local privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Python on Linux allows local privilege escalation in a
  non-default configuration. The Python multiprocessing library, when used with the forkserver
  start method on Linux, allows pickles to be deserialized from any user in the same machine local
  network namespace, which in many system configurations means any user on the same machine.
  Pickles can execute arbitrary code. Thus, this allows for local user privilege escalation to the
  user that any forkserver process is running as.");

  script_tag(name:"affected", value:"Python version 3.9.x and 3.10.x.");

  script_tag(name:"solution", value:"Update to version 3.11.0 or later.");

  script_xref(name:"URL", value:"https://python-security.readthedocs.io/vuln/multiprocessing-abstract-socket.html");
  script_xref(name:"URL", value:"https://github.com/python/cpython/issues/97514");

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

if (version_in_range_exclusive(version: version, test_version_lo: "3.9.0", test_version_up: "3.11.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.11.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

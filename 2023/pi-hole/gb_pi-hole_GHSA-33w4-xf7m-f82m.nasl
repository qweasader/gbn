# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:pi-hole:web_interface";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127318");
  script_version("2023-12-01T05:05:39+0000");
  script_tag(name:"last_modification", value:"2023-12-01 05:05:39 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-02-01 12:17:45 +0000 (Wed, 01 Feb 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-06 17:29:00 +0000 (Mon, 06 Feb 2023)");

  script_cve_id("CVE-2023-23614");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Pi-hole Web Interface 4.x < 5.8.13 Insufficient Session Expiration Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_pi-hole_http_detect.nasl");
  script_mandatory_keys("pi-hole/detected");

  script_tag(name:"summary", value:"The Pi-hole Web Interface (previously AdminLTE) is prone to an
  insufficient session expiration vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Improper use of admin WEBPASSWORD hash as
  'Remember me for 7 days' cookie value make it possible for an attacker to 'pass the hash' to
  login or reuse a theoretically expired 'remember me' cookie.");

  script_tag(name:"affected", value:"Pi-hole Web Interface (previously AdminLTE) versions starting
  from 4.0 and prior to 5.8.13.");

  script_tag(name:"solution", value:"Update to version 5.8.13 or later.");

  script_xref(name:"URL", value:"https://github.com/pi-hole/AdminLTE/security/advisories/GHSA-33w4-xf7m-f82m");

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

if (version_in_range_exclusive(version: version, test_version_lo: "4.0", test_version_up: "5.8.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.8.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

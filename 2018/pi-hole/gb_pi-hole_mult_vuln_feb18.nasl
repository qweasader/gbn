# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:pi-hole:web_interface";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108343");
  script_version("2023-12-01T05:05:39+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-12-01 05:05:39 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2018-02-18 11:43:37 +0100 (Sun, 18 Feb 2018)");
  script_name("Pi-hole Web Interface < 3.3 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_dependencies("gb_pi-hole_http_detect.nasl");
  script_mandatory_keys("pi-hole/detected");

  script_xref(name:"URL", value:"https://pi-hole.net/2018/02/14/pi-hole-v3-3-released-its-extra-special/");
  script_xref(name:"URL", value:"https://github.com/pi-hole/AdminLTE/pull/674");

  script_tag(name:"summary", value:"The Pi-hole Web Interface (previously AdminLTE) is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - not using parameterized SQL queries

  - XSS attack vectors in the php/auth.php and php/debug.php file.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct
  SQL injection and cross-site scripting (XSS) attacks.");

  script_tag(name:"affected", value:"Pi-hole Web Interface (previously AdminLTE) versions prior to
  3.3.");

  script_tag(name:"solution", value:"Update to version 3.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

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

if (version_is_less(version: version, test_version: "3.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

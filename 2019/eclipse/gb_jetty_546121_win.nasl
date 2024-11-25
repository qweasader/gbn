# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:eclipse:jetty";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142313");
  script_version("2024-06-11T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-06-11 05:05:40 +0000 (Tue, 11 Jun 2024)");
  script_tag(name:"creation_date", value:"2019-04-25 13:36:58 +0000 (Thu, 25 Apr 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-22 20:06:00 +0000 (Fri, 22 Apr 2022)");

  script_cve_id("CVE-2019-10241");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Eclipse Jetty XSS Vulnerability (CVE-2019-10241) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_jetty_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("jetty/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Eclipse Jetty is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"insight", value:"Eclipse Jetty is vulnerable to XSS conditions if a
  remote client USES a specially formatted URL against the DefaultServlet or
  ResourceHandler that is configured for showing a Listing of directory contents.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the
  target host.");

  script_tag(name:"affected", value:"Eclipse Jetty version 9.2.26 and prior, 9.3.25 and
  prior and 9.4.15 and prior.");

  script_tag(name:"solution", value:"Update to version 9.2.27.v20190403, 9.3.26.v20190403,
  9.4.16.v20190411 or later.");

  script_xref(name:"URL", value:"https://bugs.eclipse.org/bugs/show_bug.cgi?id=546121");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, version_regex: "^[0-9]+\.[0-9]+\.[0-9]+", exit_no_version: TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if (version_in_range(version: version, test_version: "9.2", test_version2: "9.2.26.20180806")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.2.27.20190403", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.3", test_version2: "9.3.25.20180904")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.3.26.20190403", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.4", test_version2: "9.4.15.20190215")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.4.16.20190411", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

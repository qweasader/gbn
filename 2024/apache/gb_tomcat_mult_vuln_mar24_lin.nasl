# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114427");
  script_version("2024-09-25T05:06:11+0000");
  script_tag(name:"last_modification", value:"2024-09-25 05:06:11 +0000 (Wed, 25 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-03-13 16:12:19 +0000 (Wed, 13 Mar 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2024-23672", "CVE-2024-24549");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat Multiple DoS Vulnerabilities (Mar 2024) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Apache Tomcat is prone to multiple denial of service (DoS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2024-23672: WebSocket DoS with incomplete closing handshake

  - CVE-2024-24549: HTTP/2 header handling DoS");

  script_tag(name:"affected", value:"Apache Tomcat versions 8.5.0 through 8.5.98, 9.0.0-M1 through
  9.0.85, 10.x through 10.1.18 and 11.0.0-M1 through 11.0.0-M16.

  Note: While not explicitly mentioned by the vendor (due to the EOL status of this branch) it is
  assumed that the whole 10.x branch is affected by this flaw.");

  script_tag(name:"solution", value:"Update to version 8.5.99, 9.0.86, 10.1.19, 11.0.0-M17 or
  later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/cmpswfx6tj4s7x0nxxosvfqs11lvdx2f");
  script_xref(name:"URL", value:"https://lists.apache.org/thread/4c50rmomhbbsdgfjsgwlb51xdwfjdcvg");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-11.html#Fixed_in_Apache_Tomcat_11.0.0-M17");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-10.html#Fixed_in_Apache_Tomcat_10.1.19");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.86");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.99");
  script_xref(name:"URL", value:"https://nowotarski.info/http2-continuation-flood/");
  script_xref(name:"URL", value:"https://nowotarski.info/http2-continuation-flood-technical-details/");

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

if (version_in_range_exclusive(version: version, test_version_lo: "8.5.0", test_version_up: "8.5.99")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.99", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.0.0.M1", test_version_up: "9.0.86")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.86", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.0.0", test_version_up: "10.1.19")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.1.19", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "11.0.0.M1", test_version_up: "11.0.0.M17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.0.0-M17", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

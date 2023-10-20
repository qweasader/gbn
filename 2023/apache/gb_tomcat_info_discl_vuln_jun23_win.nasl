# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149833");
  script_version("2023-10-12T05:05:32+0000");
  script_tag(name:"last_modification", value:"2023-10-12 05:05:32 +0000 (Thu, 12 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-06-22 03:59:49 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-28 17:56:00 +0000 (Wed, 28 Jun 2023)");

  script_cve_id("CVE-2023-34981");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat Information Disclosure Vulnerability (Jun 2023) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Apache Tomcat is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The fix for bug 66512 introduced a regression that was fixed as
  bug 66591. The regression meant that, if a response did not have any HTTP headers set, no AJP
  SEND_HEADERS message would be sent which in turn meant that at least one AJP based proxy
  (mod_proxy_ajp) would use the response headers from the previous request for the current request
  leading to an information leak.");

  script_tag(name:"affected", value:"Apache Tomcat version 8.5.88, 9.0.74, 10.1.8 and 11.0.0-M5.");

  script_tag(name:"solution", value:"Update to version 8.5.89, 9.0.75, 10.1.9, 11.0.0-M6 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/j1ksjh9m9gx1q60rtk1sbzmxhvj5h5qz");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-11.html#Fixed_in_Apache_Tomcat_11.0.0-M6");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-10.html#Fixed_in_Apache_Tomcat_10.1.9");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.75");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.89");

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

if (version_is_equal(version: version, test_version: "8.5.88")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.89", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "9.0.74")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.75", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "10.1.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.1.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "11.0.0.M5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.0.0-M6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

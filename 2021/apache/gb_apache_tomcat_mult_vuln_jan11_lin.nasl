# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:apache:tomcat";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147041");
  script_version("2023-07-06T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-06 05:05:36 +0000 (Thu, 06 Jul 2023)");
  script_tag(name:"creation_date", value:"2021-10-29 11:29:32 +0000 (Fri, 29 Oct 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2011-0013", "CVE-2010-4172", "CVE-2010-3718");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat 6.0.x < 6.0.30 Multiple Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Apache Tomcat is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2011-0013, CVE-2010-4172: Multiple cross-site scripting (XSS)

  - CVE-2010-3718: SecurityManager file permission bypass");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Apache Tomcat version 6.0.x through 6.0.29.");

  script_tag(name:"solution", value:"Update to version 6.0.30 or later.");

  script_xref(name:"URL", value:"https://tomcat.apache.org/security-6.html");

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

if (version_in_range(version: version, test_version: "6.0.0", test_version2: "6.0.29")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.30", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

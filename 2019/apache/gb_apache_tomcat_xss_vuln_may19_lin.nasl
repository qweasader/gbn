# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142479");
  script_version("2024-02-08T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-02-08 05:05:59 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2019-06-03 03:05:45 +0000 (Mon, 03 Jun 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-13 17:15:00 +0000 (Tue, 13 Jul 2021)");

  script_cve_id("CVE-2019-0221");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat XSS Vulnerability (May 2019) - Linux");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Apache Tomcat is prone to a cross-site scripting vulnerability.");

  script_tag(name:"insight", value:"The SSI printenv command in Apache Tomcat echoes user provided data without
  escaping and is, therefore, vulnerable to XSS. SSI is disabled by default. The printenv command is intended for
  debugging and is unlikely to be present in a production website.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Apache Tomcat versions 7.0.0 to 7.0.93, 8.5.0 to 8.5.39 and 9.0.0.M1 to
  9.0.17.");

  script_tag(name:"solution", value:"Update to version 7.0.94, 8.5.40, 9.0.18 or later.");

  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2019/May/50");
  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/6e6e9eacf7b28fd63d249711e9d3ccd4e0a83f556e324aee37be5a8c@%3Cannounce.tomcat.apache.org%3E");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos['version'];
path = infos['location'];

if (version_in_range(version: version, test_version: "7.0.0", test_version2: "7.0.93")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.94", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.5.0", test_version2: "8.5.39")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.40", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if ((revcomp(a: version, b: "9.0.0.M1") >= 0) && (revcomp(a: version, b: "9.0.17") <= 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.18", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

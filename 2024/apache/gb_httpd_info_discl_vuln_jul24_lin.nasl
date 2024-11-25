# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:http_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.152554");
  script_version("2024-07-05T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-07-05 05:05:40 +0000 (Fri, 05 Jul 2024)");
  script_tag(name:"creation_date", value:"2024-07-04 08:30:40 +0000 (Thu, 04 Jul 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2024-39884");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache HTTP Server 2.4.60 Information Disclosure Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_http_server_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/http_server/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Apache HTTP Server is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A regression in the core of Apache HTTP Server ignores some use
  of the legacy content-type based configuration of handlers. 'AddType' and similar configuration,
  under some circumstances where files are requested indirectly, result in source code disclosure
  of local content. For example, PHP scripts may be served instead of interpreted.");

  script_tag(name:"affected", value:"Apache HTTP Server version 2.4.60 only.");

  script_tag(name:"solution", value:"Update to version 2.4.61 or later.");

  script_xref(name:"URL", value:"https://httpd.apache.org/security/vulnerabilities_24.html#2.4.61");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE,
                                          version_regex: "^[0-9]+\.[0-9]+\.[0-9]+"))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_equal(version: version, test_version: "2.4.60")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.4.61", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:h2o_project:h2o";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140820");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-02-27 16:01:53 +0700 (Tue, 27 Feb 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-19 14:01:00 +0000 (Mon, 19 Apr 2021)");

  script_cve_id("CVE-2017-10908", "CVE-2017-10872");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("H2O HTTP Server Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_h2o_http_server_detect.nasl");
  script_mandatory_keys("h2o/installed");

  script_tag(name:"summary", value:"H2O HTTP Server is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"H2O HTTP Server is prone to multiple denial of service vulnerabilities:

  - Denial of service in the server via unspecified vectors (CVE-2017-10872)

  - Denial of service in the server via specially crafted HTTP/2 header (CVE-2017-10908)");

  script_tag(name:"affected", value:"H2O version 2.2.3 and prior.");

  script_tag(name:"solution", value:"Update to version 2.2.4 or later.");

  script_xref(name:"URL", value:"https://github.com/h2o/h2o/issues/1544");
  script_xref(name:"URL", value:"https://github.com/h2o/h2o/issues/1543");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "2.2.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.2.4");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);

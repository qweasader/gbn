# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:eclipse:jetty";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146313");
  script_version("2024-06-11T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-06-11 05:05:40 +0000 (Tue, 11 Jun 2024)");
  script_tag(name:"creation_date", value:"2021-07-16 08:30:10 +0000 (Fri, 16 Jul 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-27 14:50:00 +0000 (Tue, 27 Jul 2021)");

  script_cve_id("CVE-2021-34429");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Eclipse Jetty Information Disclosure Vulnerability (GHSA-vjv5-gp2w-65vm) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_jetty_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("jetty/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Eclipse Jetty is prone to an information disclosure
  vulnerability.");

  script_tag(name:"insight", value:"URIs can be crafted using some encoded characters to access the
  content of the WEB-INF directory and/or bypass some security constraints.

  This is a variation of the vulnerability reported in CVE-2021-28164.");

  script_tag(name:"impact", value:"The default compliance mode allows requests with URIs that
  contain a %u002e segment to access protected resources within the WEB-INF directory. For example,
  a request to /%u002e/WEB-INF/web.xml can retrieve the web.xml file. This can reveal sensitive
  information regarding the implementation of a web application. Similarly, an encoded null
  character can prevent correct normalization so that /.%00/WEB-INF/web.xml cal also retrieve the
  web.xml file.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Eclipse Jetty versions 9.4.37.v20210219 through 9.4.42.v20210604,
  10.0.1 through 10.0.5 and 11.0.1 through 11.0.5.");

  script_tag(name:"solution", value:"Update to version 9.4.43, 10.0.6, 11.0.6 or later.

  Please see the referenced vendor advisory for a possible workaround.");

  script_xref(name:"URL", value:"https://github.com/eclipse/jetty.project/security/advisories/GHSA-vjv5-gp2w-65vm");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "9.4.37.20210219", test_version2: "9.4.42.20210604")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.4.43", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.0.1", test_version2: "10.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.0.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "11.0.1", test_version2: "11.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.0.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

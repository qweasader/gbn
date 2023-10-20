# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:jquery:jquery";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143813");
  script_version("2023-07-14T05:06:08+0000");
  script_tag(name:"last_modification", value:"2023-07-14 05:06:08 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2020-05-05 06:00:22 +0000 (Tue, 05 May 2020)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)");

  script_cve_id("CVE-2020-11023");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("jQuery 1.0.3 < 3.5.0 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_jquery_consolidation.nasl");
  script_mandatory_keys("jquery/detected");

  script_tag(name:"summary", value:"jQuery is prone to a cross-site scripting (XSS) vulnerability
  when appending HTML containing option elements.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Passing HTML containing <option> elements from untrusted
  sources - even after sanitizing them - to one of jQuery's DOM manipulation methods (i.e. .html(),
  .append(), and others) may execute untrusted code.");

  script_tag(name:"affected", value:"jQuery versions starting from 1.0.3 and prior to version
  3.5.0.");

  script_tag(name:"solution", value:"Update to version 3.5.0 or later.");

  script_xref(name:"URL", value:"https://github.com/jquery/jquery/security/advisories/GHSA-jpcq-cgw6-v4j6");
  script_xref(name:"URL", value:"https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/");
  script_xref(name:"URL", value:"https://masatokinugawa.l0.cm/2020/05/jquery3.5.0-xss.html");
  script_xref(name:"URL", value:"https://security.snyk.io/vuln/SNYK-JS-JQUERY-565129");

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

if (version_in_range_exclusive(version: version, test_version_lo: "1.0.3", test_version_up: "3.5.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.5.0", install_path: location);

  extra_reporting = get_kb_item("jquery/http/" + port + "/" + location + "/extra_reporting");
  if (extra_reporting)
    report += '\nDetection info (see OID: 1.3.6.1.4.1.25623.1.0.150658 for more info):\n' + extra_reporting;

  security_message(port: port, data: report);
  exit(0);
}

exit(99);

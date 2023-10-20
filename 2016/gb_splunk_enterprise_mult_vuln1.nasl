# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = 'cpe:/a:splunk:splunk';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106399");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-11-18 13:29:17 +0700 (Fri, 18 Nov 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-09 11:29:00 +0000 (Sat, 09 Feb 2019)");

  script_cve_id("CVE-2016-5636", "CVE-2016-5699", "CVE-2016-0772");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Splunk Enterprise Multiple Vulnerabilities (Nov 2016)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_splunk_detect.nasl");
  script_mandatory_keys("Splunk/installed");

  script_tag(name:"summary", value:"Splunk Enterprise is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Splunk Enterprise is affected by multiple vulnerabilities:

  - Multiple Vulnerabilities in Python (CVE-2016-5636, CVE-2016-5699, CVE-2016-0772)

  - HTTP Request Injection in Splunk Web: Splunk Enterprise versions is affected by an HTTP request injection
vulnerability that permits leakage of authentication tokens. The authorization tokens permit an attacker to use
the Splunk REST API with the same rights as the user.");

  script_tag(name:"impact", value:"An attacker may obtain an authentication token which might give complete
access depending on the attacked user.");

  script_tag(name:"affected", value:"Splunk Enterprise 6.4.x, 6.3.x, 6.2.x, 6.1.x, 6.0.x and 5.0.x");

  script_tag(name:"solution", value:"Update to version 6.4.4, 6.3.8, 6.2.12, 6.1.12, 6.0.13, 5.0.17 or later.");

  script_xref(name:"URL", value:"http://www.splunk.com/view/SP-CAAAPSR");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^6\.4") {
  if (version_is_less(version: version, test_version: "6.4.4")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.4.4");
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^6\.3") {
  if (version_is_less(version: version, test_version: "6.3.8")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.3.8");
    security_message(port: port, data: report);
    exit(0);
  }
}


if (version =~ "^6\.2") {
  if (version_is_less(version: version, test_version: "6.2.12")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.2.12");
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^6\.1") {
  if (version_is_less(version: version, test_version: "6.1.12")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.1.12");
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^6\.0") {
  if (version_is_less(version: version, test_version: "6.0.13")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.0.13");
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version_is_less(version: version, test_version: "5.0.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.17");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);

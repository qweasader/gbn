# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:drupal:drupal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170581");
  script_version("2023-10-12T05:05:32+0000");
  script_tag(name:"last_modification", value:"2023-10-12 05:05:32 +0000 (Thu, 12 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-09-21 11:35:26 +0000 (Thu, 21 Sep 2023)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-05 14:54:00 +0000 (Thu, 05 Oct 2023)");

  script_cve_id("CVE-2023-5256");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Drupal Cache Poisoning Vulnerability (SA-CORE-2023-006) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_drupal_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Drupal is prone to a cache poisoning vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"In certain scenarios, Drupal's JSON:API module will output error
  backtraces. With some configurations, this may cause sensitive information to be cached and made
  available to anonymous users, leading to privilege escalation.");

  script_tag(name:"affected", value:"Drupal version 8.7.x, 9.x prior to 9.5.11, 10.0.x prior to
  10.0.11 and 10.1.x prior to 10.1.4.

  This vulnerability only affects sites with the JSON:API module enabled, and can be mitigated by
  uninstalling JSON:API. The core REST and contributed GraphQL modules are not affected.");

  script_tag(name:"solution", value:"Update to version 9.5.11, 10.0.11, 10.1.4 or later.");

  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2023-006");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE, version_regex: "^[0-9]+\.[0-9]+"))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "8.7.0", test_version_up: "9.5.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.5.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.0.0", test_version_up: "10.0.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.0.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.1.0", test_version_up: "10.1.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.1.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

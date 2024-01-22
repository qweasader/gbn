# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:check_mk_project:check_mk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147715");
  script_version("2023-12-20T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-12-20 05:05:58 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2022-02-28 05:20:07 +0000 (Mon, 28 Feb 2022)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-02 18:08:00 +0000 (Wed, 02 Mar 2022)");

  script_cve_id("CVE-2022-24565", "CVE-2022-24566");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Check MK 1.6 < 1.6.0p28, 2.0.x < 2.0.0p20 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_check_mk_web_detect.nasl");
  script_mandatory_keys("check_mk/detected");

  script_tag(name:"summary", value:"Check MK is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-24565: Persistent cross-site scripting (XSS) in notification configuration

  - CVE-2022-24566: Persistent cross-site scripting (XSS) in predefined conditions");

  script_tag(name:"affected", value:"Check MK version 1.6.x through 1.6.0p27 and 2.0.x through
  2.0.0p19.");

  script_tag(name:"solution", value:"Update to version 1.6.0p28, 2.0.0p20 or later.");

  script_xref(name:"URL", value:"https://checkmk.com/werk/13716");
  script_xref(name:"URL", value:"https://checkmk.com/werk/13717");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "1.6.0", test_version_up: "1.6.0p28")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.6.0p28", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "2.0.0", test_version_up: "2.0.0p20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.0.0p20", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:check_mk_project:check_mk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126354");
  script_version("2023-12-20T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-12-20 05:05:58 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-02-22 08:31:26 +0000 (Wed, 22 Feb 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-02 18:23:00 +0000 (Thu, 02 Mar 2023)");

  script_cve_id("CVE-2022-47909");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Checkmk 2.0.x < 2.0.0p29, 2.1.x < 2.1.0p12, 2.2.x < 2.2.0b1 Improper Input Validation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_check_mk_web_detect.nasl");
  script_mandatory_keys("check_mk/detected");

  script_tag(name:"summary", value:"Checkmk is prone to an improper input validation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Livestatus Query Language (LQL) injection in the AuthUser HTTP
  query header allows an attacker to perform direct queries to the application's core from
  localhost.");

  script_tag(name:"affected", value:"Checkmk versions 1.6.0 (EOL), 2.0.x prior to 2.0.0p29, 2.1.x
  prior to 2.1.0p12 and 2.2.x prior 2.2.0b1.");

  script_tag(name:"solution", value:"Update to version 2.0.0p29, 2.1.0p12, 2.2.0b1 or later.");

  script_xref(name:"URL", value:"https://checkmk.com/werk/14384");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE, service: "www" ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "1.6.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.0.0p29", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "2.0.0", test_version_up: "2.0.0p29" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.0.0p29, 2.1.0p12, 2.2.0b1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "2.1.0", test_version_up: "2.1.0p12" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.1.0p12, 2.2.0b1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "2.2.0", test_version_up: "2.2.0b1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.2.0b1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );

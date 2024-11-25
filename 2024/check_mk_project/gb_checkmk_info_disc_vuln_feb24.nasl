# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:check_mk_project:check_mk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126756");
  script_version("2024-03-25T05:05:45+0000");
  script_tag(name:"last_modification", value:"2024-03-25 05:05:45 +0000 (Mon, 25 Mar 2024)");
  script_tag(name:"creation_date", value:"2024-03-22 08:20:26 +0000 (Fri, 22 Mar 2024)");
  script_tag(name:"cvss_base", value:"1.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:P/I:N/A:N");

  script_cve_id("CVE-2024-1742");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Checkmk < 2.1.0p41, 2.2.x < 2.2.0p24 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_check_mk_web_detect.nasl");
  script_mandatory_keys("check_mk/detected");

  script_tag(name:"summary", value:"Checkmk is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"In the mk_oracle plugin sqlplus used to be called with the
  connection string as an argument. This connection string could contain credentials necessary to
  authenticate against the database. These arguments could be extracted by other users (e.g. with
  use of ps).");

  script_tag(name:"affected", value:"Checkmk versions prior to 2.1.0p41 and 2.2.x prior to
  2.2.0p24.");

  script_tag(name:"solution", value:"Update to version 2.1.0p41, 2.2.0p24 or later.");

  script_xref(name:"URL", value:"https://checkmk.com/werk/16234");

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

if( version_is_less( version: version, test_version: "2.1.0p41" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.1.0p41", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "2.2.0", test_version_up: "2.2.0p24" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.2.0p24", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );

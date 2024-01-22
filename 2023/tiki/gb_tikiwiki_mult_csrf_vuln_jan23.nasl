# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tiki:tikiwiki_cms/groupware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127302");
  script_version("2024-01-18T05:07:09+0000");
  script_tag(name:"last_modification", value:"2024-01-18 05:07:09 +0000 (Thu, 18 Jan 2024)");
  script_tag(name:"creation_date", value:"2023-01-16 12:55:19 +0000 (Mon, 16 Jan 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-23 20:00:00 +0000 (Mon, 23 Jan 2023)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2023-22852");

  script_name("Tiki Wiki < 18.10, 21.x < 21.8, 24.x < 24.3, 25.0 Multiple CSRF Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_tikiwiki_detect.nasl");
  script_mandatory_keys("TikiWiki/installed");

  script_tag(name:"summary", value:"Tiki Wiki is prone to multiple cross-site request forgery
  (CSRF) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CSRF in the /tiki-importer.php

  - CSRF in the /tiki-import_sheet.php");

  script_tag(name:"impact", value:"An attacker might force an authenticated user to import arbitrary
  sheets or arbitrary content into Tiki Wiki by tricking a victim user into browsing to a specially
  crafted web page.");

  # nb: As seen on https://sourceforge.net/projects/tikiwiki/files/ e.g. version 18.10 received an
  # update on 2023-03-01 and the 19.x and 20.x branches got updated on 2020-07-29 the last time so
  # it can be safely assumed that these are affected as well.
  script_tag(name:"affected", value:"Tiki Wiki prior to version 18.10, starting from 19.x and prior
  to 21.8, starting from 22.x and prior to 24.3 and 25.0.");

  script_tag(name:"solution", value:"Update to version 18.10, 21.8, 24.3, 25.1 or later.");

  script_xref(name:"URL", value:"https://karmainsecurity.com/KIS-2023-01");
  script_xref(name:"URL", value:"https://tiki.org/article499-New-Security-Updates-Released-and-Strongly-Recommended");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "18.10" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "18.10", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "19.0", test_version_up: "21.8" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "21.8", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "22.0", test_version_up: "24.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "24.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "25.0", test_version_up: "25.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "25.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );

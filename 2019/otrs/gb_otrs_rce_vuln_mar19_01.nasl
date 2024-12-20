# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only
###############################################################################

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.112535");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2019-03-18 09:29:11 +0100 (Mon, 18 Mar 2019)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-03 14:49:00 +0000 (Tue, 03 May 2022)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-9752");

  script_name("OTRS 7.0.x <= 7.0.3, 6.0.x <= 6.0.15 and 5.0.x <= 5.0.33 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_otrs_detect.nasl");
  script_mandatory_keys("OTRS/installed");

  script_tag(name:"summary", value:"OTRS is prone to a remote code execution (RCE) vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"impact", value:"An attacker who is logged into OTRS as an agent or a customer user may upload a
  carefully crafted resource in order to cause execution of JavaScript in the context of OTRS.");
  script_tag(name:"affected", value:"OTRS 7.0.x up to and including 7.0.3, OTRS 6.0.x up to and including 6.0.15 and OTRS 5.0.x up to and including 5.0.33.");
  script_tag(name:"solution", value:"Update to OTRS version 7.0.4, 6.0.16 or 5.0.34 respectively.");

  script_xref(name:"URL", value:"https://community.otrs.com/security-advisory-2019-01-security-update-for-otrs-framework/");

  exit(0);
}

CPE = "cpe:/a:otrs:otrs";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_in_range( version: version, test_version: "5.0.0", test_version2: "5.0.33" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.0.34" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "6.0.0", test_version2: "6.0.15" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.0.16" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "7.0.0", test_version2: "7.0.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.0.4" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

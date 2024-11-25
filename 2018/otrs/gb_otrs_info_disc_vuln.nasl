# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.112299");
  script_version("2024-09-25T05:06:11+0000");
  script_tag(name:"last_modification", value:"2024-09-25 05:06:11 +0000 (Wed, 25 Sep 2024)");
  script_tag(name:"creation_date", value:"2018-06-07 12:16:22 +0200 (Thu, 07 Jun 2018)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-07-31 17:55:00 +0000 (Tue, 31 Jul 2018)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-10198");

  script_name("OTRS 6.0.x < 6.0.7 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_otrs_detect.nasl");
  script_mandatory_keys("OTRS/installed");

  script_tag(name:"summary", value:"OTRS is prone to an Information Disclosure vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"impact", value:"An attacker who is logged into OTRS as a customer can use the ticket overview screen to disclose internal article information of their customer tickets.");
  script_tag(name:"affected", value:"OTRS 6.0.x through 6.0.6.");
  script_tag(name:"solution", value:"Update to ORTS 6.0.7.");

  script_xref(name:"URL", value:"https://community.otrs.com/security-advisory-2018-01-security-update-for-otrs-framework/");

  exit(0);
}

CPE = "cpe:/a:otrs:otrs";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_in_range( version: version, test_version: "6.0.0", test_version2: "6.0.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.0.7" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

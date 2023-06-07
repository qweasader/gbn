# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113266");
  script_version("2023-06-06T09:09:18+0000");
  script_tag(name:"last_modification", value:"2023-06-06 09:09:18 +0000 (Tue, 06 Jun 2023)");
  script_tag(name:"creation_date", value:"2018-09-11 10:48:56 +0200 (Tue, 11 Sep 2018)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-16650", "CVE-2018-16651");

  script_name("phpMyFAQ <= 2.9.10 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("phpmyfaq_detect.nasl");
  script_mandatory_keys("phpmyfaq/installed");

  script_tag(name:"summary", value:"phpMyFAQ is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"phpMyFAQ does not implement sufficient checks to avoid CSRF and
  CSV injection for the reports generated in the admin backend.

  For the CSRF and CSV injection, an attacker needs administrator privileges to be executed.");

  script_tag(name:"affected", value:"phpMyFAQ through version 2.9.10.");

  script_tag(name:"solution", value:"Update to version 2.9.11 or later.");

  script_xref(name:"URL", value:"https://www.phpmyfaq.de/security/advisory-2018-09-02");

  exit(0);
}

CPE = "cpe:/a:phpmyfaq:phpmyfaq";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! version = get_app_version( cpe: CPE, port: port ) )
  exit( 0 );

if( version_is_less( version: version, test_version: "2.9.11" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.9.11" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113436");
  script_version("2024-07-16T05:05:43+0000");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2019-07-16 10:53:25 +0000 (Tue, 16 Jul 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-16 13:29:00 +0000 (Tue, 16 Jul 2019)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-12471");

  script_name("MediaWiki >= 1.30.0, <= 1.32.1 XSS Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mediawiki_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mediawiki/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"MediaWiki is prone to a cross-site scripting (XSS) vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Loading user JavaScript from a non-existent account allows anyone to create
  the account and perform XSS on users loading that script.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to inject arbitrary JavaScript
  and HTML into the site.");
  script_tag(name:"affected", value:"MediaWiki versions 1.30.0 through 1.30.1, 1.31.0 through 1.31.1
  and 1.32.0 through 1.32.1.");
  script_tag(name:"solution", value:"Update to version 1.30.2, 1.31.2 or 1.32.2 respectively.");

  script_xref(name:"URL", value:"https://lists.wikimedia.org/pipermail/wikitech-l/2019-June/092152.html");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T207603");

  exit(0);
}

CPE = "cpe:/a:mediawiki:mediawiki";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "1.30.0", test_version2: "1.30.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.30.2", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "1.31.0", test_version2: "1.31.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.31.2", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "1.32.0", test_version2: "1.32.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.32.2", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

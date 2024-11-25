# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108092");
  script_version("2024-07-16T05:05:43+0000");
  script_cve_id("CVE-2015-6727", "CVE-2015-6728", "CVE-2015-6729", "CVE-2015-6730", "CVE-2013-7444");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2017-03-09 10:45:17 +0100 (Thu, 09 Mar 2017)");
  script_name("MediaWiki Multiple Vulnerabilities (Sep 2015) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mediawiki_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mediawiki/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"MediaWiki is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - the Special:DeletedContributions page allows remote attackers to determine if an IP is autoblocked via the 'Change block' text.

  - the ApiBase::getWatchlistUser function does not perform token comparison in constant time,
  which allows remote attackers to guess the watchlist token and bypass CSRF protection via a timing attack.

  - Cross-site scripting (XSS) vulnerability in thumb.php via the rel404 parameter, which is not properly handled in an error page.

  - Cross-site scripting (XSS) vulnerability in thumb.php via the f parameter, which is not properly handled in an error page, related to 'ForeignAPI images.'");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct XSS attacks, gain access to sensitive information and
  have other some unspecified impact.");

  script_tag(name:"affected", value:"MediaWiki before 1.23.10, 1.24.x before 1.24.3,
  and 1.25.x before 1.25.2");

  script_tag(name:"solution", value:"Upgrade to version 1.23.10 or 1.24.3
  or 1.25.2 or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"1.23.10" ) ) {
  fix = "1.23.10";
  VULN = TRUE;
}

else if( version_in_range( version:vers, test_version:"1.24.0", test_version2:"1.24.2" ) ) {
  fix = "1.24.3";
  VULN = TRUE;
}

else if( version_in_range( version:vers, test_version:"1.25.0", test_version2:"1.25.1" ) ) {
  fix = "1.25.2";
  VULN = TRUE;
}

if( VULN ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:fix );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

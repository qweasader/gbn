# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112002");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2017-08-18 15:45:02 +0200 (Fri, 18 Aug 2017)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_cve_id("CVE-2014-8958", "CVE-2014-8959");
  script_name("phpMyAdmin Multiple Vulnerabilities (PMASA-2014-13, PMASA-2014-14) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpmyadmin_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("phpMyAdmin/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"phpMyAdmin is prone to multiple cross-site scripting (XSS) and
  directory traversal vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"phpMyAdmin 4.0.x before 4.0.10.6, 4.1.x before 4.1.14.7 and
  4.2.x before 4.2.12.");

  script_tag(name:"solution", value:"Update to version 4.0.10.6, 4.1.14.7, 4.2.12 or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2014-13/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71247");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71243");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2014-14/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( vers =~ "^4\.0\." ) {
  if( version_is_less( version:vers, test_version:"4.0.10.6" ) ) {
    vuln = TRUE;
    fix = "4.0.10.6";
  }
}

if( vers =~ "^4\.1\." ) {
  if( version_is_less( version:vers, test_version:"4.1.14.7" ) ) {
    vuln = TRUE;
    fix = "4.1.14.7";
  }
}

if( vers =~ "^4\.2\." ) {
  if( version_is_less( version:vers, test_version:"4.2.12" ) ) {
    vuln = TRUE;
    fix = "4.2.12";
  }
}

if( vuln ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:fix );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

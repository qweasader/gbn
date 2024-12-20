# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108242");
  script_version("2024-02-13T05:06:26+0000");
  script_tag(name:"last_modification", value:"2024-02-13 05:06:26 +0000 (Tue, 13 Feb 2024)");
  script_tag(name:"creation_date", value:"2017-09-11 08:48:02 +0200 (Mon, 11 Sep 2017)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_cve_id("CVE-2011-2642", "CVE-2011-2719");
  script_name("phpMyAdmin 3.x < 3.3.10.3, 3.4.x < 3.4.3.2 Multiple Vulnerabilities (PMASA-2011-9, PMASA-2011-12) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpmyadmin_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("phpMyAdmin/installed", "Host/runs_unixoide");

  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2011-9/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48874");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2011-12/");

  script_tag(name:"summary", value:"phpMyAdmin is prone to multiple vulnerabilities:

  - a Cross-Site Scripting (XSS) vulnerability in table Print view

  - possible superglobal and local variables manipulation in swekey authentication.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"phpMyAdmin 3.x before 3.3.10.3 and 3.4.x before 3.4.3.2.");

  script_tag(name:"solution", value:"Update to version 3.3.10.3, 3.4.3.2 or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( vers =~ "^3\.[0-3]\." ) {
  if( version_is_less( version:vers, test_version:"3.3.10.3" ) ) {
    vuln = TRUE;
    fix = "3.3.10.3";
  }
}

if( vers =~ "^3\.4\." ) {
  if( version_is_less( version:vers, test_version:"3.4.3.2" ) ) {
    vuln = TRUE;
    fix = "3.4.3.2";
  }
}

if( vuln ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:fix );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

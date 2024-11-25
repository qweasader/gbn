# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801060");
  script_version("2024-02-19T05:05:57+0000");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-12-04 14:17:59 +0100 (Fri, 04 Dec 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-4018", "CVE-2009-2626");
  script_name("PHP Multiple Vulnerabilities (Dec 2009)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/37482");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36009");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37138");
  script_xref(name:"URL", value:"http://bugs.php.net/bug.php?id=49026");
  script_xref(name:"URL", value:"http://securityreason.com/achievement_securityalert/65");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2009/11/23/15");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Error in 'proc_open()' function in 'ext/standard/proc_open.c' that does not
  enforce the 'safe_mode_allowed_env_vars' and 'safe_mode_protected_env_vars'
  directives, which allows attackers to execute programs with an arbitrary
  environment via the env parameter.

  - Error in 'zend_restore_ini_entry_cb()' function in 'zend_ini.c', which
  allows attackers to obtain sensitive information.");

  script_tag(name:"impact", value:"Successful exploitation could allow local attackers to bypass certain
  security restrictions and cause denial of service.");

  script_tag(name:"affected", value:"PHP version 5.2.10 and prior. PHP version 5.3.x before 5.3.1");

  script_tag(name:"solution", value:"Update to version 5.3.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"5.2.11" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.2.11" );
  security_message( port:port, data:report );
  exit( 0 );
} else if( vers =~ "^5\.3" ) {
  if( version_is_less( version:vers, test_version:"5.3.1" ) ) {
    report = report_fixed_ver( installed_version:vers, fixed_version:"5.3.1" );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

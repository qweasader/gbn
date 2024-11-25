# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808604");
  script_version("2024-02-23T14:36:45+0000");
  script_cve_id("CVE-2015-8867", "CVE-2015-8876", "CVE-2015-8873", "CVE-2015-8835");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-23 14:36:45 +0000 (Fri, 23 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-14 18:48:00 +0000 (Thu, 14 Feb 2019)");
  script_tag(name:"creation_date", value:"2016-07-14 12:14:00 +0530 (Thu, 14 Jul 2016)");
  script_name("PHP < 5.4.44, 5.5.x < 5.5.28, 5.6.x < 5.6.12 Multiple Vulnerabilities (Jul 2016) - Linux");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An improper validation of certain Exception objects in 'Zend/zend_exceptions.c'
    script.

  - The 'openssl_random_pseudo_bytes' function in 'ext/openssl/openssl.c' incorrectly
    relies on the deprecated 'RAND_pseudo_bytes' function.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to cause a denial of service (NULL pointer dereference and
  application crash) or trigger unintended method execution to defeat cryptographic
  protection mechanisms.");

  script_tag(name:"affected", value:"PHP versions prior to 5.4.44, 5.5.x before
  5.5.28, and 5.6.x before 5.6.12 on Linux");

  script_tag(name:"solution", value:"Update to version 5.4.44, 5.5.28, 5.6.12 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/87481");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/90867");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/84426");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/90712");

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_unixoide");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( phpPort = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) ) exit( 0 );

if(version_is_less(version:phpVer, test_version:"5.4.44"))
{
  fix = '5.4.44';
  VULN = TRUE;
}

else if(phpVer =~ "^5\.5")
{
  if(version_in_range(version:phpVer, test_version:"5.5.0", test_version2:"5.5.27"))
  {
    fix = '5.5.28';
    VULN = TRUE;
  }
}

else if(phpVer =~ "^5\.6")
{
  if(version_in_range(version:phpVer, test_version:"5.6.0", test_version2:"5.6.11"))
  {
    fix = '5.5.12';
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:phpVer, fixed_version:fix);
  security_message(data:report, port:phpPort);
  exit(0);
}

exit(99);

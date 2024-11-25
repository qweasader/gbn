# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807092");
  script_version("2024-02-08T05:05:59+0000");
  script_cve_id("CVE-2015-5590", "CVE-2015-8838", "CVE-2015-5589");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-08 05:05:59 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)");
  script_tag(name:"creation_date", value:"2016-03-01 16:56:54 +0530 (Tue, 01 Mar 2016)");
  script_name("PHP 'phar_fix_filepath' Function Stack Buffer Overflow Vulnerability (Mar 2016) - Windows");

  script_tag(name:"summary", value:"PHP is prone to a stack buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to

  - Inadequate boundary checks on user-supplied input by 'phar_fix_filepath'
    function in 'ext/phar/phar.c' script.

  - Improper validation of file pointer in the 'phar_convert_to_other'
    function in 'ext/phar/phar_object.c' script.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to execute arbitrary code in the context of the PHP process.
  Failed exploit attempts will likely crash the webserver.");

  script_tag(name:"affected", value:"PHP versions before 5.4.43, 5.5.x before
  5.5.27, and 5.6.x before 5.6.11 on Windows");

  script_tag(name:"solution", value:"Update to PHP version 5.4.43, or 5.5.27, or
  5.6.11 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75970");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/88763");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75974");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=69923");

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( phpPort = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) ) exit( 0 );

if(version_is_less(version:phpVer, test_version:"5.4.43"))
{
  fix = '5.4.43';
  VULN = TRUE;
}

else if(phpVer =~ "^5\.6")
{
  if(version_is_less(version:phpVer, test_version:"5.6.11"))
  {
    fix = '5.6.11';
    VULN = TRUE;
  }
}

else if(phpVer =~ "^5\.5")
{
  if(version_is_less(version:phpVer, test_version:"5.5.27"))
  {
    fix = '5.5.27';
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

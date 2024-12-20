# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808198");
  script_version("2024-02-23T14:36:45+0000");
  script_cve_id("CVE-2016-4070", "CVE-2016-4071", "CVE-2016-4072", "CVE-2016-4073",
                "CVE-2015-8865");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-23 14:36:45 +0000 (Fri, 23 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)");
  script_tag(name:"creation_date", value:"2016-07-14 12:14:00 +0530 (Thu, 14 Jul 2016)");
  script_name("PHP < 5.5.34, 5.6.x < 5.6.20, 7.0.x < 7.0.5 Multiple Vulnerabilities (Jul 2016) - Windows");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Multiple integer overflows in the mbfl_strcut function in
    'ext/mbstring/libmbfl/mbfl/mbfilter.c' script.

  - Format string vulnerability in the php_snmp_error function in
    'ext/snmp/snmp.c' script.

  - An improper handling of '\0' characters by the 'phar_analyze_path' function
    in 'ext/phar/phar.c' script.

  - An integer overflow in the 'php_raw_url_encode' function in
    'ext/standard/url.c' script.

  - An improper handling of continuation-level jumps in 'file_check_mem'
    function in 'funcs.c' script.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to cause a denial of service (buffer overflow and application
  crash) or possibly execute arbitrary code.");

  script_tag(name:"affected", value:"PHP versions prior to 5.5.34, 5.6.x before
  5.6.20, and 7.0.x before 7.0.5 on Windows");

  script_tag(name:"solution", value:"Update to version 5.5.34, 5.6.20, 7.0.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/85800");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/85801");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/85802");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/85991");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/85993");
  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-7.php");

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

if(version_is_less(version:phpVer, test_version:"5.5.34"))
{
  fix = '5.5.34';
  VULN = TRUE;
}

else if(phpVer =~ "^5\.6")
{
  if(version_in_range(version:phpVer, test_version:"5.6.0", test_version2:"5.6.19"))
  {
    fix = '5.6.20';
    VULN = TRUE;
  }
}

else if(phpVer =~ "^7\.0")
{
  if(version_in_range(version:phpVer, test_version:"7.0", test_version2:"7.0.4"))
  {
    fix = '7.0.5';
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

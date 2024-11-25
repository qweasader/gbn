# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808611");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2015-8877", "CVE-2015-8879", "CVE-2015-8874");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-29 20:43:00 +0000 (Mon, 29 Aug 2022)");
  script_tag(name:"creation_date", value:"2016-07-14 12:14:00 +0530 (Thu, 14 Jul 2016)");
  script_name("PHP Multiple Denial of Service Vulnerabilities - Linux");

  script_tag(name:"summary", value:"PHP is prone to multiple denial of service (DoS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to

  - An improper handling of driver behavior for SQL_WVARCHAR columns in the
    'odbc_bindcols function' in 'ext/odbc/php_odbc.c' script.

  - The 'gdImageScaleTwoPass' function in gd_interpolation.c script in the
    GD Graphics Library uses inconsistent allocate and free approaches.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to cause a denial of service (application crash or
  memory consuption).");

  script_tag(name:"affected", value:"PHP versions prior to 5.6.12 on Linux");

  script_tag(name:"solution", value:"Update to PHP version 5.6.12
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/90866");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/90842");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/90714");

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_unixoide");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( phpPort = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) ) exit( 0 );

if(version_is_less(version:phpVer, test_version:"5.6.12"))
{
  report = report_fixed_ver(installed_version:phpVer, fixed_version:"5.6.12");
  security_message(data:report, port:phpPort);
  exit(0);
}

exit(99);
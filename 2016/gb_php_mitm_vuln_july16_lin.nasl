# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808628");
  script_version("2024-02-08T05:05:59+0000");
  script_cve_id("CVE-2016-5385", "CVE-2016-6128");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-08 05:05:59 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-29 16:17:00 +0000 (Wed, 29 Sep 2021)");
  script_tag(name:"creation_date", value:"2016-07-26 11:55:14 +0530 (Tue, 26 Jul 2016)");
  script_name("PHP Man-in-the-Middle Attack Vulnerability (Jul 2016) - Linux");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_unixoide");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91821");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91509");
  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-7.php");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/797896");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=72573");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=72494");

  script_tag(name:"summary", value:"PHP is prone to a man-in-the-middle attack vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - The web servers running in a CGI or CGI-like context may assign client request proxy header values to internal
  HTTP_PROXY environment variables.

  - 'HTTP_PROXY' is improperly trusted by some PHP libraries and applications

  - An unspecified flaw in  the gdImageCropThreshold
  function in 'gd_crop.c' in the GD Graphics Library.");

  script_tag(name:"impact", value:"Successfully exploiting this issue may allow
  remote, unauthenticated to conduct MITM attacks on internal server subrequests
  or direct the server to initiate connections to arbitrary hosts or to cause a
  denial of service.");

  script_tag(name:"affected", value:"PHP versions 5.x through 5.6.23 and 7.0.x through 7.0.8 on Linux");

  script_tag(name:"solution", value:"Update to PHP version 5.6.24 or 7.0.19.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( phpPort = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) ) exit( 0 );

if( version_is_less_equal( version:phpVer, test_version:"5.6.23" )
    || version_in_range( version:phpVer, test_version:"7.0", test_version2:"7.0.8" ) ) {
  report = report_fixed_ver(installed_version:phpVer, fixed_version:"5.6.24/7.0.9");
  security_message( data:report, port:phpPort );
  exit( 0 );
}

exit( 99 );

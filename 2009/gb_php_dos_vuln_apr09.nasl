# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800393");
  script_version("2024-02-19T05:05:57+0000");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-04-23 08:49:13 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-1272");
  script_name("PHP DoS Vulnerability (Apr 2009)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_xref(name:"URL", value:"http://www.php.net/releases/5_2_9.php");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2009/04/01/9");

  script_tag(name:"impact", value:"Successful exploitation could result in denial of service condition.");

  script_tag(name:"affected", value:"PHP version prior to 5.2.9");

  script_tag(name:"insight", value:"Improper handling of .zip file while doing extraction via
  php_zip_make_relative_path function in php_zip.c file.");

  script_tag(name:"solution", value:"Update to version 5.2.9 or later.");

  script_tag(name:"summary", value:"PHP is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( phpPort = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) ) exit( 0 );

if( version_is_less( version:phpVer, test_version:"5.2.9" ) ) {
  report = report_fixed_ver( installed_version:phpVer, fixed_version:"5.2.9" );
  security_message( data:report, port:phpPort );
  exit( 0 );
}

exit( 99 );

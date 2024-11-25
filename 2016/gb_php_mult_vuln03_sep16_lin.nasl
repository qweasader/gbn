# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809317");
  script_version("2024-02-08T05:05:59+0000");
  script_cve_id("CVE-2016-7412", "CVE-2016-7413", "CVE-2016-7414", "CVE-2016-7416",
                "CVE-2016-7417", "CVE-2016-7418");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-08 05:05:59 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-05-04 01:29:00 +0000 (Fri, 04 May 2018)");
  script_tag(name:"creation_date", value:"2016-09-12 18:19:30 +0530 (Mon, 12 Sep 2016)");
  script_name("PHP Multiple Vulnerabilities - 03 (Sep 2016) - Linux");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Use-after-free vulnerability in the 'wddx_stack_destroy' function
    in 'ext/wddx/wddx.c' script.

  - Improper verification of a BIT field has the UNSIGNED_FLAG flag
    in 'ext/mysqlnd/mysqlnd_wireprotocol.c' script.

  - The ZIP signature-verification feature does not ensure that the
    uncompressed_filesize field is large enough.

  - The script 'ext/spl/spl_array.c' proceeds with SplArray unserialization
    without validating a return value and data type.

  - The script 'ext/intl/msgformat/msgformat_format.c' does not properly restrict
    the locale length provided to the Locale class in the ICU library.

  - An error in the php_wddx_push_element function in ext/wddx/wddx.c.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to cause a denial of service, or possibly have unspecified
  other impact.");

  script_tag(name:"affected", value:"PHP versions prior to 5.6.25 and
  7.x before 7.0.10 on Linux");

  script_tag(name:"solution", value:"Update to PHP version 5.6.25, or 7.0.10,
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-7.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93005");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93006");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93004");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93022");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93008");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93007");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93011");
  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");

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

if(version_is_less(version:phpVer, test_version:"5.6.26"))
{
  fix = "5.6.26";
  VULN = TRUE;
}

else if(phpVer =~ "^7\.0")
{
  if(version_in_range(version:phpVer, test_version:"7.0", test_version2:"7.0.10"))
  {
    fix = "7.0.11";
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

# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808787");
  script_version("2024-02-08T05:05:59+0000");
  script_cve_id("CVE-2016-5773", "CVE-2016-5772", "CVE-2016-5769", "CVE-2016-5768",
                "CVE-2016-5766", "CVE-2016-5767");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-08 05:05:59 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)");
  script_tag(name:"creation_date", value:"2016-08-17 11:41:54 +0530 (Wed, 17 Aug 2016)");
  script_name("PHP Multiple Vulnerabilities - 01 (Aug 2016) - Windows");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - The 'php_zip.c' script in the zip extension improperly interacts with the
    unserialize implementation and garbage collection.

  - The php_wddx_process_data function in 'wddx.c' script in the WDDX extension
    mishandled data in a wddx_deserialize call.

  - The multiple integer overflows in 'mcrypt.c' script in the mcrypt extension.

  - The double free vulnerability in the '_php_mb_regex_ereg_replace_exec'
    function in 'php_mbregex.c' script in the mbstring extension.

  - An integer overflow in the '_gd2GetHeader' function in 'gd_gd2.c' script in
    the GD Graphics Library.

  - An integer overflow in the 'gdImageCreate' function in 'gd.c' script in the
    GD Graphics Library.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to cause a denial of service (buffer overflow and application
  crash) or possibly execute arbitrary code.");

  script_tag(name:"affected", value:"PHP versions prior to 5.5.37, 5.6.x before
  5.6.23, and 7.x before 7.0.8 on Windows");

  script_tag(name:"solution", value:"Update to PHP version 5.5.37, or 5.6.23,
  or 7.0.8, or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91397");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91398");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91399");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91396");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91395");
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

if(version_is_less(version:phpVer, test_version:"5.5.37"))
{
  fix = '5.5.37';
  VULN = TRUE;
}

else if(phpVer =~ "^5\.6")
{
  if(version_in_range(version:phpVer, test_version:"5.6.0", test_version2:"5.6.22"))
  {
    fix = '5.6.23';
    VULN = TRUE;
  }
}

else if(phpVer =~ "^7\.0")
{
  if(version_in_range(version:phpVer, test_version:"7.0", test_version2:"7.0.7"))
  {
    fix = '7.0.8';
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

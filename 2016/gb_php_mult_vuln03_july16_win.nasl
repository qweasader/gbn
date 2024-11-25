# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808602");
  script_version("2024-02-23T14:36:45+0000");
  script_cve_id("CVE-2016-4537", "CVE-2016-4538", "CVE-2016-4539", "CVE-2016-4540",
                "CVE-2016-4541", "CVE-2016-4542", "CVE-2016-4543", "CVE-2016-4544");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-23 14:36:45 +0000 (Fri, 23 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-20 16:55:00 +0000 (Wed, 20 Jul 2022)");
  script_tag(name:"creation_date", value:"2016-07-14 12:14:00 +0530 (Thu, 14 Jul 2016)");
  script_name("PHP < 5.5.35, 5.6.x < 5.6.21, 7.0.x < 7.0.6 Multiple Vulnerabilities (Jul 2016) - Windows");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An improper validation of TIFF start data in 'exif_process_TIFF_in_JPEG' function
    in 'ext/exif/exif.c' script.

  - An improper validation of IFD sizes in 'exif_process_TIFF_in_JPEG' function
    in 'ext/exif/exif.c' script.

  - An improper construction of spprintf arguments, in 'exif_process_TIFF_in_JPEG'
    function in 'ext/exif/exif.c' script.

  - An error in 'grapheme_strpos function' in 'ext/intl/grapheme/grapheme_string.c'.

  - An error in 'xml_parse_into_struct' function in 'ext/xml/xml.c' script.

  - The 'bcpowmod' function in 'ext/bcmath/bcmath.c' improperly modifies certain data
    structures.

  - An improper validation of input passed to 'bcpowmod' function in
    'ext/bcmath/bcmath.c' script.

  - An error in 'grapheme_strpos' function in ext/intl/grapheme/grapheme_string.c
    script.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to cause a denial of service (out-of-bounds read) or possibly
  have unspecified other impact.");

  script_tag(name:"affected", value:"PHP versions prior to 5.5.35, 5.6.x before
  5.6.21, and 7.0.x before 7.0.6 on Windows.");

  script_tag(name:"solution", value:"Update to version 5.5.35, 5.6.21, 7.0.6 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/89844");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/90172");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/90173");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/90174");
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

if(version_is_less(version:phpVer, test_version:"5.5.35"))
{
  fix = '5.5.35';
  VULN = TRUE;
}

else if(phpVer =~ "^5\.6")
{
  if(version_in_range(version:phpVer, test_version:"5.6.0", test_version2:"5.6.20"))
  {
    fix = '5.6.21';
    VULN = TRUE;
  }
}

else if(phpVer =~ "^7\.0")
{
  if(version_in_range(version:phpVer, test_version:"7.x", test_version2:"7.0.5"))
  {
    fix = '7.0.6';
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

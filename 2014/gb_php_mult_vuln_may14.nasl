# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804291");
  script_version("2024-02-19T05:05:57+0000");
  script_cve_id("CVE-2013-7226", "CVE-2013-7327", "CVE-2013-7328", "CVE-2014-2020");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-05-09 09:47:32 +0530 (Fri, 09 May 2014)");
  script_name("PHP Multiple Vulnerabilities - 01 (May 2014)");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1065108");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65533");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65656");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65668");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65676");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Integer overflow in the 'gdImageCrop' function within ext/gd/gd.c script.

  - Improper data types check as using string or array data type in place of
  a numeric data type within ext/gd/gd.c script.

  - Multiple integer signedness errors in the 'gdImageCrop' function within
  ext/gd/gd.c script.

  - Some NULL pointer dereference errors related to the 'imagecrop' function
  implementation.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct denial of
  service, gain sensitive information and have some other unspecified impacts.");

  script_tag(name:"affected", value:"PHP version 5.5.x before 5.5.9");

  script_tag(name:"solution", value:"Update to PHP version 5.5.9 or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if(version_in_range( version:vers, test_version:"5.5.0", test_version2:"5.5.8" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.5.9" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

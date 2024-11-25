# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808796");
  script_version("2024-02-08T05:05:59+0000");
  script_cve_id("CVE-2016-3132");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-08 05:05:59 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-28 20:06:00 +0000 (Mon, 28 Nov 2016)");
  script_tag(name:"creation_date", value:"2016-08-17 15:02:21 +0530 (Wed, 17 Aug 2016)");
  script_name("PHP Arbitrary Code Execution Vulnerability (Jul 2016) - Linux");

  script_tag(name:"summary", value:"PHP is prone to an arbitrary code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to the double free
  vulnerability in the 'SplDoublyLinkedList::offsetSet' function in
  'ext/spl/spl_dllist.c' script.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow remote
  attackers to execute arbitrary code via a crafted index.");

  script_tag(name:"affected", value:"PHP versions 7.x before 7.0.6 on Linux");

  script_tag(name:"solution", value:"Update to PHP version 7.0.6,
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-7.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92356");

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

if(version_in_range(version:phpVer, test_version:"7.0.0", test_version2:"7.0.5"))
{
  report = report_fixed_ver(installed_version:phpVer, fixed_version:"7.0.6");
  security_message(data:report, port:phpPort);
  exit(0);
}

exit(99);

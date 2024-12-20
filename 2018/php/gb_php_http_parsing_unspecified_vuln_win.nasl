# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813903");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2018-14884");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-19 11:15:00 +0000 (Mon, 19 Aug 2019)");
  script_tag(name:"creation_date", value:"2018-08-07 13:05:15 +0530 (Tue, 07 Aug 2018)");
  script_name("PHP 'HTTP Parsing' Function Unspecified Vulnerability - Windows");

  script_tag(name:"summary", value:"PHP is prone to an unspecified vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an inappropriate parsing
  of HTTP response 'http_header_value' in 'ext/standard/http_fopen_wrapper.c'.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to cause segmentation fault.");

  script_tag(name:"affected", value:"PHP versions 7.0.x before 7.0.27, 7.1.x
  before 7.1.13, and 7.2.x before 7.2.1 on Windows.");

  script_tag(name:"solution", value:"Update to PHP version 7.0.27, 7.1.13 or
  7.2.1 or later. Please see the references for more information.");

  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=75535");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(phpPort = get_app_port(cpe:CPE))) exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:phpPort, exit_no_version:TRUE)) exit(0);
phpVers = infos['version'];
path = infos['location'];

if(version_in_range(version:phpVers, test_version:"7.0", test_version2:"7.0.26")){
  fix = "7.0.27";
}

else if(version_in_range(version:phpVers, test_version:"7.1", test_version2:"7.1.12")){
  fix = "7.1.13";
}

else if(phpVers == "7.2.0"){
  fix = "7.2.1";
}

if(fix)
{
  report = report_fixed_ver(installed_version:phpVers, fixed_version:fix, install_path:path);
  security_message(port:phpPort, data:report);
  exit(0);
}

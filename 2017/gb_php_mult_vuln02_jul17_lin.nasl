# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811409");
  script_version("2024-02-23T14:36:45+0000");
  script_cve_id("CVE-2017-11362", "CVE-2017-12934");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-23 14:36:45 +0000 (Fri, 23 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-22 16:29:00 +0000 (Wed, 22 May 2019)");
  script_tag(name:"creation_date", value:"2017-08-01 10:20:01 +0530 (Tue, 01 Aug 2017)");
  script_name("PHP 7.0.x < 7.0.21, 7.1.x < 7.1.7 Multiple Vulnerabilities (Jul 2017) - Linux)");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_unixoide");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-7.php");
  script_xref(name:"URL", value:"http://bugs.php.net/73473");
  script_xref(name:"URL", value:"http://bugs.php.net/74101");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - Fixed bug #73473 (Stack Buffer Overflow in msgfmt_parse_message). (CVE-2017-11362)

  - Fixed bug #74101 (Unserialize Heap Use-After-Free (READ: 1) in zval_get_type). (CVE-2017-12934)");

  script_tag(name:"affected", value:"PHP versions 7.0.x before 7.0.21 and 7.1.x before 7.1.7.");

  script_tag(name:"solution", value:"Update to version 7.0.21, 7.1.7 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
loc = infos["location"];

if(vers =~ "^7\.0" && version_is_less(version:vers, test_version:"7.0.21"))
  fix = "7.0.21";

else if(vers =~ "^7\.1" && version_is_less(version:vers, test_version:"7.1.7"))
  fix = "7.1.7";

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:loc);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

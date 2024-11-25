# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108053");
  script_version("2024-02-23T14:36:45+0000");
  script_cve_id("CVE-2016-10161", "CVE-2016-10158", "CVE-2016-10168", "CVE-2016-10167", "CVE-2017-11147",
                "CVE-2016-10160", "CVE-2016-10159");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-23 14:36:45 +0000 (Fri, 23 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-20 16:58:00 +0000 (Wed, 20 Jul 2022)");
  script_tag(name:"creation_date", value:"2017-01-25 11:00:00 +0100 (Wed, 25 Jan 2017)");
  script_name("PHP < 5.6.30, 7.0.x < 7.0.15, 7.1.x < 7.1.1 Multiple Vulnerabilities (Jan 2017) - Windows");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-7.php");
  script_xref(name:"URL", value:"http://bugs.php.net/73825");
  script_xref(name:"URL", value:"http://bugs.php.net/73737");
  script_xref(name:"URL", value:"http://bugs.php.net/73869");
  script_xref(name:"URL", value:"http://bugs.php.net/73868");
  script_xref(name:"URL", value:"http://bugs.php.net/73773");
  script_xref(name:"URL", value:"http://bugs.php.net/73768");
  script_xref(name:"URL", value:"http://bugs.php.net/73764");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - Fixed bug #73825 (Heap out of bounds read on unserialize in finish_nested_data()).
  (CVE-2016-10161)

  - Fixed bug #73737 (FPE when parsing a tag format). (CVE-2016-10158)

  - Fixed bug #73869 (Signed Integer Overflow gd_io.c). (CVE-2016-10168)

  - Fixed bug #73868 (DOS vulnerability in gdImageCreateFromGd2Ctx()). (CVE-2016-10167)

  - Fixed bug #73773 (Seg fault when loading hostile phar). (CVE-2017-11147)

  - Fixed bug #73768 (Memory corruption when loading hostile phar). (CVE-2016-10160)

  - Fixed bug #73764 (Crash while loading hostile phar archive). (CVE-2016-10159)");

  script_tag(name:"affected", value:"PHP versions before 5.6.30, 7.0.x before 7.0.15 and 7.1.x
  before 7.1.1.");

  script_tag(name:"solution", value:"Update to version 5.6.30, 7.0.15, 7.1.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

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

if(version_is_less(version:vers, test_version:"5.6.30"))
  fix = "5.6.30";

else if(version_in_range(version:vers, test_version:"7.0", test_version2:"7.0.14"))
  fix = "7.0.15";

else if(vers =~ "^7\.1" && version_is_less(version:vers, test_version:"7.1.1"))
  fix = "7.1.1";

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:loc);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

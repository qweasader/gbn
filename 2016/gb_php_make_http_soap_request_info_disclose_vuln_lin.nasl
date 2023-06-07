# Copyright (C) 2016 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808666");
  script_version("2021-10-07T10:33:09+0000");
  script_cve_id("CVE-2016-3185");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-10-07 10:33:09 +0000 (Thu, 07 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-01 03:09:00 +0000 (Thu, 01 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-08-31 12:31:36 +0530 (Wed, 31 Aug 2016)");
  script_name("PHP 'make_http_soap_request' DoS / Information Disclosure Vulnerability - Linux");

  script_tag(name:"summary", value:"PHP is prone to a denial of service (DoS) and an information
  disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due an error in the 'make_http_soap_request'
  function of the 'ext/soap/php_http.c' script.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow remote attackers to
  obtain sensitive information from process memory or cause a denial of service.");

  script_tag(name:"affected", value:"PHP versions prior to 5.4.44, 5.5.x before 5.5.28, 5.6.x before
  5.6.12, and 7.x before 7.0.4.");

  script_tag(name:"solution", value:"Update to version 5.4.44, 5.5.28, 5.6.12, 7.0.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-7.php");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_unixoide");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:vers, test_version:"5.4.44")) {
  fix = "5.4.44";
  VULN = TRUE;
}

else if(vers =~ "^5\.5") {
  if(version_in_range(version:vers, test_version:"5.5.0", test_version2:"5.5.27")) {
    fix = "5.5.28";
    VULN = TRUE;
  }
}

else if(vers =~ "^5\.6") {
  if(version_in_range(version:vers, test_version:"5.6.0", test_version2:"5.6.11")) {
    fix = "5.6.12";
    VULN = TRUE;
  }
}

else if(vers =~ "^7\.0") {
  if(version_in_range(version:vers, test_version:"7.0", test_version2:"7.0.3")) {
    fix = "7.0.4";
    VULN = TRUE;
  }
}

if(VULN) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
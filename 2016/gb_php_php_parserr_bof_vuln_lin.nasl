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
  script_oid("1.3.6.1.4.1.25623.1.0.809743");
  script_version("2022-04-13T13:17:10+0000");
  script_cve_id("CVE-2014-4049");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-13 13:17:10 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"creation_date", value:"2016-12-05 17:24:03 +0530 (Mon, 05 Dec 2016)");
  script_name("PHP 'php_parserr' Heap Based Buffer Overflow Vulnerability (Linux)");

  script_tag(name:"summary", value:"PHP is prone to a heap-based buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to buffer overflow error
  in the 'php_parserr' function in ext/standard/dns.c script.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allows remote
  attackers to cause a denial of service (crash) and possibly execute arbitrary code
  on the affected system.");

  script_tag(name:"affected", value:"PHP versions 5.6.x alpha and beta releases
  before 5.6.0, 5.5.x before 5.5.14, 5.4.x before 5.4.30, 5.3.x before 5.3.29
  on Linux");

  script_tag(name:"solution", value:"Update to PHP version 5.6.0 or 5.5.14 or
  5.4.30 or 5.3.29 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68007");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2014/06/13/4");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

if(vers =~ "^5\.")
{
  ## 5.6.0alpha1, 5.6.0alpha2, 5.6.0alpha3, 5.6.0alpha4, 5.6.0alpha5
  ## 5.6.0beta1, 5.6.0beta2, 5.6.0beta3, 5.6.0beta4
  if(vers =~ "^5\.6\.0alpha" || vers =~ "^5\.6\.0beta")
  {
    VULN = TRUE;
    fix = "5.6.0";
  }

  if(version_in_range(version:vers, test_version:"5.3",test_version2:"5.3.28"))
  {
    VULN = TRUE;
    fix = "5.3.29";
  }

  else if(version_in_range(version:vers, test_version:"5.4",test_version2:"5.4.29"))
  {
    VULN = TRUE;
    fix = "5.4.30";
  }

  else if(version_in_range(version:vers, test_version:"5.5",test_version2:"5.5.13"))
  {
    VULN = TRUE;
    fix = "5.5.14";
  }

  if(VULN)
  {
    report = report_fixed_ver(installed_version:vers, fixed_version:fix);
    security_message(data:report, port:port);
    exit(0);
  }
}

exit(99);

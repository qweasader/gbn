# Copyright (C) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.804639");
  script_version("2022-04-14T11:24:11+0000");
  script_cve_id("CVE-2014-0237", "CVE-2014-0238");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-04-14 11:24:11 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2014-06-16 10:22:50 +0530 (Mon, 16 Jun 2014)");
  script_name("PHP CDF File Parsing Denial of Service Vulnerabilities - 01 - Jun14");

  script_tag(name:"summary", value:"PHP is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to

  - An error due to an infinite loop within the 'unpack_summary_info' function in
  src/cdf.c script.

  - An error within the 'cdf_read_property_info' function in src/cdf.c script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct denial of
  service attacks.");

  script_tag(name:"affected", value:"PHP version 5.x before 5.4.29 and 5.5.x before 5.5.13");

  script_tag(name:"solution", value:"Update to PHP version 5.4.29 or 5.5.13 or later.");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67759");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67765");
  script_xref(name:"URL", value:"http://secunia.com/advisories/58804");
  script_xref(name:"URL", value:"https://www.hkcert.org/my_url/en/alert/14060401");

  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_in_range(version:vers, test_version:"5.5.0", test_version2:"5.5.12")||
   version_in_range(version:vers, test_version:"5.0.0", test_version2:"5.4.28")){
  report = report_fixed_ver(installed_version:vers, fixed_version:"5.4.29/5.5.13");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);

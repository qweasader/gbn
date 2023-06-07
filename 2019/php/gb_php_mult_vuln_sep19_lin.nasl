# Copyright (C) 2019 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108637");
  script_version("2021-04-13T14:13:08+0000");
  script_tag(name:"last_modification", value:"2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)");
  script_tag(name:"creation_date", value:"2019-09-09 08:48:28 +0000 (Mon, 09 Sep 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP Multiple Vulnerabilities - Sep19 (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"PHP is prone to multiple vulnerabilities:

  - Buffer overflow in zendparse

  - Cast to object confuses GC, causes crash

  - Exif crash (bus error) due to wrong alignment and invalid cast

  - Use-after-free in FPM master event handling");

  script_tag(name:"affected", value:"PHP versions before 7.2.22 and 7.3.x before 7.3.9.");

  script_tag(name:"solution", value:"Update to version 7.2.22, 7.3.9 or later.");

  script_xref(name:"URL", value:"http://bugs.php.net/78363");
  script_xref(name:"URL", value:"http://bugs.php.net/78379");
  script_xref(name:"URL", value:"http://bugs.php.net/78333");
  script_xref(name:"URL", value:"http://bugs.php.net/77185");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-7.php#7.3.9");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-7.php#7.2.22");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos['version'];
path = infos['location'];

if (version_is_less(version: version, test_version: "7.2.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.22", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.3", test_version2: "7.3.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.3.9", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

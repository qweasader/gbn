# Copyright (C) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.802670");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2012-3450");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-08-27 17:03:25 +0530 (Mon, 27 Aug 2012)");
  script_name("PHP pdo_sql_parser.re 'PDO' extension DoS vulnerability (Windows)");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2012/Jun/60");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54777");
  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=61755");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=769785");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to cause a denial of
  service condition.");

  script_tag(name:"affected", value:"PHP version before 5.3.14 and 5.4.x before 5.4.4 on Windows");

  script_tag(name:"insight", value:"The flaw is due to an error in the PDO extension in pdo_sql_parser.re
  file, which fails to determine the end of the query string during parsing of
  prepared statements.");

  script_tag(name:"solution", value:"Update to PHP Version 5.3.14 or 5.4.4 or later.");

  script_tag(name:"summary", value:"PHP is prone to a denial of service vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:vers, test_version:"5.3.14") ||
   version_in_range(version:vers, test_version: "5.4.0", test_version2: "5.4.3")){
  report = report_fixed_ver(installed_version:vers, fixed_version:"5.3.14/5.4.4");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);

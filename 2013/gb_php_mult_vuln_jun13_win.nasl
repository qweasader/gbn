# Copyright (C) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.803678");
  script_version("2022-04-25T14:50:49+0000");
  script_cve_id("CVE-2013-4635", "CVE-2013-2110");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-06-25 17:29:19 +0530 (Tue, 25 Jun 2013)");
  script_name("PHP Multiple Vulnerabilities - Jun13 (Windows)");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60411");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60731");
  script_xref(name:"URL", value:"http://bugs.php.net/bug.php?id=64895");
  script_xref(name:"URL", value:"http://bugs.php.net/bug.php?id=64879");
  script_xref(name:"URL", value:"http://www.security-database.com/detail.php?alert=CVE-2013-4635");
  script_xref(name:"URL", value:"http://www.security-database.com/detail.php?alert=CVE-2013-2110");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to execute arbitrary code or cause
  denial of service condition via crafted arguments.");

  script_tag(name:"affected", value:"PHP version before 5.3.26 and 5.4.x before 5.4.16");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Heap-based overflow in 'php_quot_print_encode' function in
    'ext/standard/quot_print.c' script.

  - Integer overflow in the 'SdnToJewish' function in 'jewish.c' in the
    Calendar component.");

  script_tag(name:"solution", value:"Update to PHP 5.4.16 or 5.3.26 or later.");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

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

if(version_is_less(version:vers, test_version:"5.3.26")||
  version_in_range(version:vers, test_version:"5.4.0", test_version2: "5.4.15")){
  report = report_fixed_ver(installed_version:vers, fixed_version:"5.3.26/5.4.16");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);

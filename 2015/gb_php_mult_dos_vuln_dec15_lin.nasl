# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.806649");
  script_version("2022-04-14T06:42:08+0000");
  script_cve_id("CVE-2015-7804", "CVE-2015-7803");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-14 06:42:08 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2015-12-15 17:44:53 +0530 (Tue, 15 Dec 2015)");
  script_name("PHP Multiple Denial of Service Vulnerabilities - 01 - Dec15 (Linux)");

  script_tag(name:"summary", value:"PHP is prone to multiple denial of service (DoS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An Off-by-one error in the 'phar_parse_zipfile' function within ext/phar/zip.c
    script.

  - An error in the 'phar_get_entry_data' function in ext/phar/util.c script.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to cause a denial of service (NULL pointer dereference and
  application crash).");

  script_tag(name:"affected", value:"PHP versions before 5.5.30 and 5.6.x
  before 5.6.14");

  script_tag(name:"solution", value:"Update to PHP 5.5.30 or 5.6.14 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76959");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=70433");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2015/10/05/8");

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_unixoide");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( phpPort = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) ) exit( 0 );

if(phpVer =~ "^5\.6")
{
  if(version_in_range(version:phpVer, test_version:"5.6.0", test_version2:"5.6.13"))
  {
    fix = "5.6.14";
    VULN = TRUE;
  }
}

else if(version_is_less(version:phpVer, test_version:"5.5.30"))
{
  fix = "5.5.30";
  VULN = TRUE;
}

if(VULN)
{
  report = 'Installed Version: ' + phpVer + '\n' +
           'Fixed Version:     ' + fix + '\n';
  security_message(data:report, port:phpPort);
  exit(0);
}

exit(99);
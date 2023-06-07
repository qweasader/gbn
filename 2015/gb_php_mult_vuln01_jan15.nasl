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
  script_oid("1.3.6.1.4.1.25623.1.0.805409");
  script_version("2022-04-14T06:42:08+0000");
  script_cve_id("CVE-2014-3670", "CVE-2014-3669", "CVE-2014-3668");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-14 06:42:08 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2015-01-06 17:18:33 +0530 (Tue, 06 Jan 2015)");
  script_name("PHP Multiple Vulnerabilities - 01 - Jan15");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - The exif_ifd_make_value function in exif.c in the EXIF extension in PHP
    operates on floating-point arrays incorrectly.

  - Integer overflow in the object_custom function in ext/standard/var
    _unserializer.c in PHP.

  - Buffer overflow in the date_from_ISO8601 function in the mkgmtime
    implementation in libxmlrpc/xmlrpc.c in the XMLRPC extension in PHP.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service or possibly execute arbitrary code
  via different crafted dimensions.");

  script_tag(name:"affected", value:"PHP versions 5.4.x before 5.4.34, 5.5.x
  before 5.5.18, and 5.6.x before 5.6.2");

  script_tag(name:"solution", value:"Update to PHP version 5.4.34 or 5.5.18
  or 5.6.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=68044");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70611");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70665");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70666");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( phpPort = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) ) exit( 0 );

if(phpVer =~ "^5\.[4-6]")
{
  if(version_in_range(version:phpVer, test_version:"5.4.0", test_version2:"5.4.33")||
     version_in_range(version:phpVer, test_version:"5.5.0", test_version2:"5.5.17")||
     version_in_range(version:phpVer, test_version:"5.6.0", test_version2:"5.6.1")) {
    report = report_fixed_ver(installed_version:phpVer, fixed_version:"5.4.34/5.5.18/5.6.2");
    security_message(data:report, port:phpPort);
    exit(0);
  }
}

exit(99);

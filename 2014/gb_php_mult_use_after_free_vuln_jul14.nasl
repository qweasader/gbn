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
  script_oid("1.3.6.1.4.1.25623.1.0.804682");
  script_version("2022-04-14T11:24:11+0000");
  script_cve_id("CVE-2014-4698", "CVE-2014-4670");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-14 11:24:11 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2014-07-18 14:56:10 +0530 (Fri, 18 Jul 2014)");
  script_name("PHP Multiple Use-After-Free Vulnerabilities - Jul14");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=67539");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68511");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68513");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=67538");
  script_xref(name:"URL", value:"http://git.php.net/?p=php-src.git;a=patch;h=df78c48354f376cf419d7a97f88ca07d572f00fb");
  script_xref(name:"URL", value:"http://git.php.net/?p=php-src.git;a=patch;h=22882a9d89712ff2b6ebc20a689a89452bba4dcd");

  script_tag(name:"summary", value:"PHP is prone to multiple use-after-free vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws are due to an use-after-free error related to SPL iterators
  and ArrayIterators.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct denial of
  service attacks or possibly have some other unspecified impact.");

  script_tag(name:"affected", value:"PHP version 5.x through 5.5.14");

  script_tag(name:"solution", value:"Apply the updates/patches from the referenced links.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( phpPort = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) ) exit( 0 );

if(phpVer =~ "^5\.5"){
  if(version_in_range(version:phpVer, test_version:"5.5.0", test_version2:"5.5.14")){
    report = report_fixed_ver(installed_version:phpVer, fixed_version:"5.5.15");
    security_message(data:report, port:phpPort);
    exit(0);
  }
}

exit(99);

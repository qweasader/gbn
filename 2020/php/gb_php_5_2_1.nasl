# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108862");
  script_version("2022-04-13T07:21:45+0000");
  script_tag(name:"last_modification", value:"2022-04-13 07:21:45 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"creation_date", value:"2020-08-17 06:44:26 +0000 (Mon, 17 Aug 2020)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2006-6383", "CVE-2007-0905", "CVE-2007-0906", "CVE-2007-0907", "CVE-2007-0908",
                "CVE-2007-0909", "CVE-2007-0910", "CVE-2007-0988", "CVE-2007-1376", "CVE-2007-1380",
                "CVE-2007-1383", "CVE-2007-1452", "CVE-2007-1453", "CVE-2007-1454", "CVE-2007-1700",
                "CVE-2007-1701", "CVE-2007-1824", "CVE-2007-1825", "CVE-2007-1835", "CVE-2007-1884",
                "CVE-2007-1885", "CVE-2007-1886", "CVE-2007-1887", "CVE-2007-1889", "CVE-2007-1890",
                "CVE-2007-4441", "CVE-2007-4586");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/21508");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/22496");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/22805");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/22806");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/22862");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/22922");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/23119");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/23120");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/23219");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/23233");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/23234");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/23235");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/23236");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/23237");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/23238");
  script_name("PHP < 5.2.1 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"affected", value:"PHP before version 5.2.1.");

  script_tag(name:"solution", value:"Update PHP to version 5.2.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"5.2.1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"5.2.1", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

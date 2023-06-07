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
  script_oid("1.3.6.1.4.1.25623.1.0.108870");
  script_version("2022-04-13T07:21:45+0000");
  script_tag(name:"last_modification", value:"2022-04-13 07:21:45 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"creation_date", value:"2020-08-17 06:44:26 +0000 (Mon, 17 Aug 2020)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2006-7243", "CVE-2010-2094", "CVE-2010-2950", "CVE-2010-3436",
                "CVE-2010-3709", "CVE-2010-3710", "CVE-2010-3870", "CVE-2010-4150",
                "CVE-2010-4156", "CVE-2010-4409", "CVE-2010-4697", "CVE-2010-4698",
                "CVE-2010-4699", "CVE-2010-4700", "CVE-2011-0753", "CVE-2011-0754",
                "CVE-2011-0755");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40173");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43926");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44605");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44718");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44723");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44951");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44980");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45119");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45335");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45338");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45339");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45952");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45954");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46056");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46168");
  script_name("PHP < 5.3.4 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"affected", value:"PHP before version 5.3.4.");

  script_tag(name:"solution", value:"Update PHP to version 5.3.4 or later.");

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

if( version_is_less( version:version, test_version:"5.3.4" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"5.3.4", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

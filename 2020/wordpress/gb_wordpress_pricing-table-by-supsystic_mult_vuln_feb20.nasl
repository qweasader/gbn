# Copyright (C) 2020 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112707");
  script_version("2023-01-17T10:10:58+0000");
  script_tag(name:"last_modification", value:"2023-01-17 10:10:58 +0000 (Tue, 17 Jan 2023)");
  script_tag(name:"creation_date", value:"2020-02-28 12:43:11 +0000 (Fri, 28 Feb 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-25 15:08:00 +0000 (Wed, 25 Mar 2020)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-9392", "CVE-2020-9393", "CVE-2020-9394");

  script_name("WordPress Pricing Table by Supsystic Plugin < 1.8.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/pricing-table-by-supsystic/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Pricing Table by Supsystic' is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2020-9392: incorrect default permissions

  - CVE-2020-9393: cross-site scripting

  - CVE-2020-9394: cross-site request forgery");

  script_tag(name:"affected", value:"WordPress plugin Pricing Table by Supsystic before version 1.8.2.");

  script_tag(name:"solution", value:"Update to version 1.8.2 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/pricing-table-by-supsystic/#developers");

  exit(0);
}

CPE = "cpe:/a:supsystic:pricing_table_by_supsystic";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "1.8.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.8.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );

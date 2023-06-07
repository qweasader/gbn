# Copyright (C) 2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112567");
  script_version("2023-01-23T10:11:56+0000");
  script_tag(name:"last_modification", value:"2023-01-23 10:11:56 +0000 (Mon, 23 Jan 2023)");
  script_tag(name:"creation_date", value:"2019-04-17 16:05:00 +0200 (Wed, 17 Apr 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-07 05:15:00 +0000 (Sat, 07 Sep 2019)");

  script_cve_id("CVE-2018-17583", "CVE-2018-17584", "CVE-2018-17585", "CVE-2018-17586");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Fastest Cache Plugin < 0.8.8.6 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-fastest-cache/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Fastest Cache' is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to inject malicious
  content into an affected site or to force an end user to execute unwanted actions on the web
  application.");

  script_tag(name:"affected", value:"WordPress Fastest Cache plugin before version 0.8.8.6.");

  script_tag(name:"solution", value:"Update to version 0.8.8.6 or later.");

  script_xref(name:"URL", value:"https://ansawaf.blogspot.com/2019/04/csrf-multiple-stored-xss-in-wp-fastest.html");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/wp-fastest-cache/#developers");

  exit(0);
}

CPE = "cpe:/a:wpfastestcache:wp_fastest_cache";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "0.8.8.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "0.8.8.6", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );

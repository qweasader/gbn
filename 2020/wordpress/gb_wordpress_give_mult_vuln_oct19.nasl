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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112819");
  script_version("2023-02-21T10:19:50+0000");
  script_tag(name:"last_modification", value:"2023-02-21 10:19:50 +0000 (Tue, 21 Feb 2023)");
  script_tag(name:"creation_date", value:"2020-09-01 11:05:11 +0000 (Tue, 01 Sep 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-26 17:55:00 +0000 (Mon, 26 Oct 2020)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-20627");

  script_name("WordPress GiveWP Plugin < 2.5.10 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/give/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'GiveWP' is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"There are multiple authenticated and unauthenticated settings change vulnerabilities.
  Additionally the 'give_get_ip' function in 'includes/misc-functions.php' lacks proper validation
  and will accept arbitrary IP addresses in the 'Client-IP' field.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to
  disable all email notifications sent to the admin or have other unspecified impact.");

  script_tag(name:"affected", value:"WordPress GiveWP plugin through version 2.5.9.");

  script_tag(name:"solution", value:"Update to version 2.5.10 or later.");

  script_xref(name:"URL", value:"https://blog.nintechnet.com/multiple-vulnerabilities-fixed-in-wordpress-givewp-plugin/");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/give/#developers");

  exit(0);
}

CPE = "cpe:/a:givewp:givewp";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "2.5.10" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.5.10", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

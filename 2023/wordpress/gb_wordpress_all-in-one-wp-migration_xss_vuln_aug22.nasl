# Copyright (C) 2023 Greenbone Networks GmbH
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

CPE = "cpe:/a:servmask:one-stop_wp_migration";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127321");
  script_version("2023-02-07T12:10:58+0000");
  script_tag(name:"last_modification", value:"2023-02-07 12:10:58 +0000 (Tue, 07 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-03 07:02:19 +0000 (Fri, 03 Feb 2023)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2022-2546");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress All-in-One WP Migration Plugin < 7.63 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/all-in-one-wp-migration/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'All-in-One WP Migration' is prone to a
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin uses the wrong content type, and does not properly
  escape the response from the ai1wm_export AJAX action.");

  script_tag(name:"impact", value:"A malicious attacker is able to craft a request that when
  submitted by any visitor will inject arbitrary HTML or JavaScript into the response that will be
  executed in the victim's session.");

  script_tag(name:"affected", value:"WordPress All-in-One WP Migration plugin prior to version
  7.63.");

  script_tag(name:"solution", value:"Update to version 7.63 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/f84920e4-a1fe-47cf-9ba5-731989c70f58");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "7.63" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.63", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );

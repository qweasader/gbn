# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.142583");
  script_version("2022-07-19T10:11:08+0000");
  script_tag(name:"last_modification", value:"2022-07-19 10:11:08 +0000 (Tue, 19 Jul 2022)");
  script_tag(name:"creation_date", value:"2019-07-11 07:00:14 +0000 (Thu, 11 Jul 2019)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Live Chat Support Plugin < 8.0.27 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-live-chat-support/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Live Chat Support' is prone to a persistent cross-site
  scripting vulnerability in the option update.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"WordPress Live Chat Support plugin before version 8.0.27.");

  script_tag(name:"solution", value:"Update to version 8.0.27 or later.");

  script_xref(name:"URL", value:"https://blog.sucuri.net/2019/05/persistent-cross-site-scripting-in-wp-live-chat-support-plugin.html");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/wp-live-chat-support/#developers");

  exit(0);
}

CPE = "cpe:/a:3cx:wp-live-chat-support";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if ( version_is_less( version: version, test_version: "8.0.27" )) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.0.27", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
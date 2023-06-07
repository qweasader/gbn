# Copyright (C) 2023 Greenbone Networks GmbH
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

CPE = "cpe:/a:adenion:blog2social";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170278");
  script_version("2023-01-13T10:21:10+0000");
  script_tag(name:"last_modification", value:"2023-01-13 10:21:10 +0000 (Fri, 13 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-11 17:29:25 +0000 (Wed, 11 Jan 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2022-3246", "CVE-2022-3247");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Blog2Social Plugin < 6.9.10 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/blog2social/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Blog2Social' is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-3246: The plugin does not properly sanitise and escape a parameter before using it in a
  SQL statement, leading to a SQL injection exploitable by any authenticated users, such as
  subscribers.

  - CVE-2022-3247: The plugin does not have authorisation in an AJAX action, and does not ensure that
  the URL to make a request to is an external one. As a result, any authenticated users, such as
  subscriber could perform SSRF attacks.");

  script_tag(name:"affected", value:"WordPress Blog2Social plugin prior to version 6.9.10.");

  script_tag(name:"solution", value:"Update to version 6.9.10 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/ece049b2-9a21-463d-9e8b-b4ce61919f0c");
  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/ee312f22-ca58-451d-a1cb-3f78a6e5ecaf");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"6.9.10" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"6.9.10", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

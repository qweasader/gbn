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
  script_oid("1.3.6.1.4.1.25623.1.0.113630");
  script_version("2023-10-20T16:09:12+0000");
  script_tag(name:"last_modification", value:"2023-10-20 16:09:12 +0000 (Fri, 20 Oct 2023)");
  script_tag(name:"creation_date", value:"2020-01-24 09:27:36 +0000 (Fri, 24 Jan 2020)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-28 18:13:00 +0000 (Tue, 28 Jan 2020)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-7047", "CVE-2020-7048");

  script_name("WordPress Database Reset Plugin <= 3.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wordpress-database-reset/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'WP Database Reset' is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Any authenticated user with minimal permissions can escalate their privileges
    to administrator while dropping all other users from the table with a
    wp-admin/admin.php?db-reset-tables[]=users request.

  - Any unauthenticated user can reset any table in the database to the initial
    WordPress set-up state (deleting all site content stored in that table) via
    the wp-admin/admin-post.php?db-reset-tables[]=comments URI.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to wipe all of the
  site's data or even gain complete control over the target system.");

  script_tag(name:"affected", value:"WordPress Database Reset plugin through version 3.1.");

  script_tag(name:"solution", value:"Update to version 3.15.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/wordpress-database-reset/#developers");
  script_xref(name:"URL", value:"https://wpvulndb.com/vulnerabilities/10027");
  script_xref(name:"URL", value:"https://wpvulndb.com/vulnerabilities/10028");
  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2020/01/easily-exploitable-vulnerabilities-patched-in-wp-database-reset-plugin/");

  exit(0);
}

CPE = "cpe:/a:webfactoryltd:wp_database_reset";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "3.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.15", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

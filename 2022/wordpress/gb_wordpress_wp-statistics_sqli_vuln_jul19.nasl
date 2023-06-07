# Copyright (C) 2022 Greenbone Networks GmbH
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

CPE = "cpe:/a:veronalabs:wp_statistics";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127075");
  script_version("2022-07-19T10:11:08+0000");
  script_tag(name:"last_modification", value:"2022-07-19 10:11:08 +0000 (Tue, 19 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-07-08 09:52:09 +0000 (Fri, 08 Jul 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-10 13:50:00 +0000 (Wed, 10 Jul 2019)");

  script_cve_id("CVE-2019-13275");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress WP Statistics Plugin <= 12.6.6 SQLi Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-statistics/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'WP Statistics' is prone to an SQL injection
  (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An endpoint of the API, which is exposed when the
  'use cache plugin' setting is enabled (by default disabled), is vulnerable to an unauthenticated
  blind SQLi issue.");

  script_tag(name:"affected", value:"WordPress WP Statistics plugin version 12.6.6 and prior.");

  script_tag(name:"solution", value:"Update to version 12.6.7 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/9412");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/wp-statistics/#developers");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less_equal(version: version, test_version: "12.6.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12.6.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

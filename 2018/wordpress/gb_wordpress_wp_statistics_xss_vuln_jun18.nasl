# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.813453");
  script_version("2022-07-19T10:11:08+0000");
  script_cve_id("CVE-2018-1000556");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-07-19 10:11:08 +0000 (Tue, 19 Jul 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-20 12:56:00 +0000 (Mon, 20 Aug 2018)");
  script_tag(name:"creation_date", value:"2018-06-27 12:29:51 +0530 (Wed, 27 Jun 2018)");

  script_name("WordPress WP Statistics < 12.0.6 XSS Vulnerability");

  script_tag(name:"summary", value:"The WordPress plugin 'WP Statistics' is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to the lack of sanitization
  in user-provided data for '/includes/log/page-statistics.php' script  via
  'page-uri' parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML code via crafted data.");

  script_tag(name:"affected", value:"WordPress WP Statistics plugin prior to
  version 12.0.6.");

  script_tag(name:"solution", value:"Update to WordPress WP Statistics plugin
  12.0.6 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/wp-statistics/#developers");
  script_xref(name:"URL", value:"https://www.pluginvulnerabilities.com/2017/04/28/reflected-cross-site-scripting-xss-vulnerability-in-wp-statistics/");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-statistics/detected");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE)) {
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE)) {
  exit(0);
}

version = infos["version"];
location = infos["location"];

if(version_is_less(version:version, test_version:"12.0.6")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"12.0.6", install_path:location);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);

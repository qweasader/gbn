# Copyright (C) 2021 Greenbone Networks GmbH
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

CPE = "cpe:/a:draftpress:header_footer_code_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147167");
  script_version("2022-07-19T10:11:08+0000");
  script_tag(name:"last_modification", value:"2022-07-19 10:11:08 +0000 (Tue, 19 Jul 2022)");
  script_tag(name:"creation_date", value:"2021-11-16 03:36:07 +0000 (Tue, 16 Nov 2021)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-10 13:48:00 +0000 (Wed, 10 Nov 2021)");

  script_cve_id("CVE-2021-24791");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Header Footer Code Manager Plugin < 1.1.14 SQLi Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/header-footer-code-manager/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Header Footer Code Manager' is prone to an
  SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not validate and escape the 'orderby' and
  'order' request parameters before using them in a SQL statement when viewing the Snippets admin
  dashboard, leading to SQL injections.");

  script_tag(name:"affected", value:"WordPress Header Footer Code Manager version 1.1.13 and prior.");

  script_tag(name:"solution", value:"Update to version 1.1.14 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/d55caa9b-d50f-4c13-bc69-dc475641735f");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/header-footer-code-manager/#developers");

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

if (version_is_less(version: version, test_version: "1.1.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.1.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

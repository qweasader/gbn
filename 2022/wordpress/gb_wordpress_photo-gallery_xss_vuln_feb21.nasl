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

CPE = "cpe:/a:10web:photo_gallery";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147922");
  script_version("2022-07-19T10:11:08+0000");
  script_tag(name:"last_modification", value:"2022-07-19 10:11:08 +0000 (Tue, 19 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-04-05 03:55:04 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-07 01:25:00 +0000 (Tue, 07 Dec 2021)");

  script_cve_id("CVE-2021-25041");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Photo Gallery Plugin < 1.5.68 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/photo-gallery/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Photo Gallery' is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin is vulnerable to reflected XSS issues via the
  bwg_album_breadcrumb_0 and shortcode_id GET parameters passed to the bwg_frontend_data AJAX
  action.");

  script_tag(name:"affected", value:"WordPress Photo Gallery plugin before version 1.5.68.");

  script_tag(name:"solution", value:"Update to version 1.5.68 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/32aee3ea-e0af-44da-a16c-102c83eaed8f");

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

if (version_is_less(version: version, test_version: "1.5.68")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.5.68", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

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

CPE = "cpe:/a:admincolumns:admin_columns";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146330");
  script_version("2022-11-10T10:12:04+0000");
  script_tag(name:"last_modification", value:"2022-11-10 10:12:04 +0000 (Thu, 10 Nov 2022)");
  script_tag(name:"creation_date", value:"2021-07-20 03:58:54 +0000 (Tue, 20 Jul 2021)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-15 14:29:00 +0000 (Thu, 15 Jul 2021)");

  script_cve_id("CVE-2021-24365");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Admin Columns plugin < 4.3.2 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/codepress-admin-columns/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Admin Columns' is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Admin Columns WordPress plugin allowed to configure individual
  columns for tables. Each column had a type. The type 'Custom Field' allowed to choose an arbitrary
  database column to display in the table. There was no escaping applied to the contents of
  'Custom Field' columns.");

  script_tag(name:"affected", value:"WordPress Admin Columns plugin prior to version 4.3.2.");

  script_tag(name:"solution", value:"Update to version 4.3.2 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/codepress-admin-columns/#developers");
  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/fdbeb137-b404-46c7-85fb-394a3bdac388");

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

if (version_is_less(version: version, test_version: "4.3.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

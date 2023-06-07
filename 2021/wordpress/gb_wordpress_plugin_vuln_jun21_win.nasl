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

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147225");
  script_version("2023-03-01T10:20:05+0000");
  script_tag(name:"last_modification", value:"2023-03-01 10:20:05 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"creation_date", value:"2021-11-26 01:52:11 +0000 (Fri, 26 Nov 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-30 07:16:00 +0000 (Tue, 30 Nov 2021)");

  script_cve_id("CVE-2021-44223");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress < 5.8 Missing 'Update URI' Plugin Header Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("wordpress/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"WordPress is prone to a missing 'Update URI' plugin header
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"WordPress lacks support for the Update URI plugin header. This
  makes it easier for remote attackers to execute arbitrary code via a supply-chain attack against
  WordPress installations that use any plugin for which the slug satisfies the naming constraints
  of the WordPress.org Plugin Directory but is not yet present in that directory.");

  script_tag(name:"affected", value:"WordPress prior to version 5.8.");

  script_tag(name:"solution", value:"Update to version 5.8 or later.");

  script_xref(name:"URL", value:"https://make.wordpress.org/core/2021/06/29/introducing-update-uri-plugin-header-in-wordpress-5-8/");
  script_xref(name:"URL", value:"https://vavkamil.cz/2021/11/25/wordpress-plugin-confusion-update-can-get-you-pwned/");

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

if (version_is_less(version: version, test_version: "5.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

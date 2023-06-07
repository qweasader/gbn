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

CPE = "cpe:/a:wp-events-plugin:events_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147260");
  script_version("2022-11-21T10:11:06+0000");
  script_tag(name:"last_modification", value:"2022-11-21 10:11:06 +0000 (Mon, 21 Nov 2022)");
  script_tag(name:"creation_date", value:"2021-12-06 06:33:02 +0000 (Mon, 06 Dec 2021)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-03 13:39:00 +0000 (Fri, 03 Dec 2021)");

  script_cve_id("CVE-2020-35012", "CVE-2020-35037");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Events Manager Plugin < 5.9.8 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/events-manager/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Events Manager' is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2020-35012: SQL injection (SQLi)

  - CVE-2020-35037: Cross-site scripting (XSS)");

  script_tag(name:"affected", value:"WordPress Events Manager plugin prior to version 5.9.8.");

  script_tag(name:"solution", value:"Update to version 5.9.8 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/323140b1-66c4-4e7d-85a4-1c922e40866f");
  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/937b9bdb-7e8e-4ea8-82ec-aa5f6bd70619");

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

if (version_is_less(version: version, test_version: "5.9.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.9.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

# Copyright (C) 2019 Greenbone Networks GmbH
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

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142898");
  script_version("2021-08-30T11:01:18+0000");
  script_tag(name:"last_modification", value:"2021-08-30 11:01:18 +0000 (Mon, 30 Aug 2021)");
  script_tag(name:"creation_date", value:"2019-09-17 06:20:33 +0000 (Tue, 17 Sep 2019)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-28 18:15:00 +0000 (Sat, 28 Sep 2019)");

  script_cve_id("CVE-2019-12922");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpMyAdmin < 4.9.1 CSRF Vulnerability (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_phpmyadmin_detect_900129.nasl", "os_detection.nasl");
  script_mandatory_keys("phpMyAdmin/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"phpMyAdmin is prone to a CSRF vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A CSRF issue in phpMyAdmin allows deletion of any server in the Setup page.");

  script_tag(name:"affected", value:"phpMyAdmin version 4.9.0.1 and prior.");

  script_tag(name:"solution", value:"Update to phpMyAdmin version 4.9.1 or later.");

  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2019/Sep/23");
  script_xref(name:"URL", value:"https://github.com/phpmyadmin/phpmyadmin/commit/7d21d4223bdbe0306593309132b4263d7087d13b");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if (version_is_less(version: version, test_version: "4.9.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.9.1", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:djangoproject:django";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143585");
  script_version("2021-08-16T12:00:57+0000");
  script_tag(name:"last_modification", value:"2021-08-16 12:00:57 +0000 (Mon, 16 Aug 2021)");
  script_tag(name:"creation_date", value:"2020-03-06 03:09:42 +0000 (Fri, 06 Mar 2020)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-18 15:05:00 +0000 (Tue, 18 Aug 2020)");

  script_cve_id("CVE-2020-9402");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Django 1.11.x < 1.11.29, 2.2.x < 2.2.11, 3.0.x < 3.0.4 SQL Injection Vulnerability (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_django_detect_win.nasl");
  script_mandatory_keys("django/windows/detected");

  script_tag(name:"summary", value:"Django is prone to an SQL injection vulnerability.");

  script_tag(name:"insight", value:"Django allows SQL Injection if untrusted data is used as a tolerance parameter
  in GIS functions and aggregates on Oracle. By passing a suitably crafted tolerance to GIS functions and
  aggregates on Oracle, it was possible to break escaping and inject malicious SQL.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Django versions 1.11.x, 2.2.x and 3.0.x.");

  script_tag(name:"solution", value:"Update to version 1.11.29, 2.2.11, 3.0.4 or later.");

  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2020/mar/04/security-releases/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "1.11.0", test_version2: "1.11.28")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.11.29", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "2.2.0", test_version2: "2.2.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.2.11", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.0.0", test_version2: "3.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.4", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

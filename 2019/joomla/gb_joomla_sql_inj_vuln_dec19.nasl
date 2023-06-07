# Copyright (C) 2019 Greenbone Networks GmbH
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

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143289");
  script_version("2021-09-02T13:01:30+0000");
  script_tag(name:"last_modification", value:"2021-09-02 13:01:30 +0000 (Thu, 02 Sep 2021)");
  script_tag(name:"creation_date", value:"2019-12-20 05:09:01 +0000 (Fri, 20 Dec 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-18 20:10:00 +0000 (Wed, 18 Dec 2019)");

  script_cve_id("CVE-2019-19846");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Joomla! 2.5.0 - 3.9.13 SQL Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");

  script_tag(name:"summary", value:"Joomla! is prone to an SQL injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The lack of validation of configuration parameters used in SQL queries caused
  various SQL injection vectors.");

  script_tag(name:"affected", value:"Joomla! versions 2.5.0 - 3.9.13.");

  script_tag(name:"solution", value:"Update to version 3.9.14.");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre.html");

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

if (version_in_range(version: version, test_version: "2.5.0", test_version2: "3.9.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.14", install_path: location);
  security_message(data: report, port: port);
  exit(0);
}

exit(99);

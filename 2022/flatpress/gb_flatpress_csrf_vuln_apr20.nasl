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

CPE = "cpe:/a:flatpress:flatpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147685");
  script_version("2022-02-23T14:03:34+0000");
  script_tag(name:"last_modification", value:"2022-02-23 14:03:34 +0000 (Wed, 23 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-22 09:07:49 +0000 (Tue, 22 Feb 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-03 23:43:00 +0000 (Tue, 03 Aug 2021)");

  script_cve_id("CVE-2020-22761");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("FlatPress < 1.1.1 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_flatpress_http_detect.nasl");
  script_mandatory_keys("flatpress/detected");

  script_tag(name:"summary", value:"FlatPress is prone to a cross-site request forgery (CSRF)
  vulnerability via the DeleteFile function in flat/admin.php.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"FlatPress version 1.1 and prior.");

  script_tag(name:"solution", value:"Update to version 1.1.1 or later.");

  script_xref(name:"URL", value:"https://github.com/flatpressblog/flatpress/issues/64");

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

if (version_is_less(version: version, test_version: "1.1.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.1.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

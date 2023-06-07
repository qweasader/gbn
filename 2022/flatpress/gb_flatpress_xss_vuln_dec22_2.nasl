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
  script_oid("1.3.6.1.4.1.25623.1.0.118427");
  script_version("2022-12-20T10:11:13+0000");
  script_tag(name:"last_modification", value:"2022-12-20 10:11:13 +0000 (Tue, 20 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-12-19 11:00:29 +0000 (Mon, 19 Dec 2022)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2022-40047");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("FlatPress 1.2.1 XSS Vulnerability (CVE-2022-40047)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_flatpress_http_detect.nasl");
  script_mandatory_keys("flatpress/detected");

  script_tag(name:"summary", value:"FlatPress is prone to a cross-site scripting (XSS)
  vulnerability via the page parameter at '/flatpress/admin.php'.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"FlatPress version 1.2.1.");

  script_tag(name:"solution", value:"No known solution is available as of 19th December, 2022.
  Information regarding this issue will be updated once solution details are available.

  Note: The vendor has added a fix into the master repository with commit '0a7ad2c'. No
  new version containing the fix has been released yet.");

  script_xref(name:"URL", value:"https://github.com/flatpressblog/flatpress/issues/153");
  script_xref(name:"URL", value:"https://github.com/flatpressblog/flatpress/commit/0a7ad2ccb8533b54654907726b48bd7da44e715c");

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

if (version_is_equal(version: version, test_version: "1.2.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See solution", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);

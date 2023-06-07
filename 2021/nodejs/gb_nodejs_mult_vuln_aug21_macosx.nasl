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

CPE = "cpe:/a:nodejs:node.js";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146531");
  script_version("2022-09-22T10:44:54+0000");
  script_tag(name:"last_modification", value:"2022-09-22 10:44:54 +0000 (Thu, 22 Sep 2022)");
  script_tag(name:"creation_date", value:"2021-08-19 12:20:20 +0000 (Thu, 19 Aug 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-24 13:54:00 +0000 (Tue, 24 Aug 2021)");

  script_cve_id("CVE-2021-3672", "CVE-2021-22931", "CVE-2021-22939", "CVE-2021-22940");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Node.js 12.x, 14.x, 16.x Multiple Vulnerabilities (Aug 2021) - Mac OS X");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_nodejs_detect_macosx.nasl");
  script_mandatory_keys("Nodejs/MacOSX/Ver");

  script_tag(name:"summary", value:"Node.js is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-3672, CVE-2021-22931: Improper handling of untypical characters in domain names

  - CVE-2021-22940: Use after free on close http2 on stream canceling

  - CVE-2021-22939: Incomplete validation of rejectUnauthorized parameter");

  script_tag(name:"affected", value:"Node.js 12.x, 14.x and 16.x.");

  script_tag(name:"solution", value:"Update to version 12.22.5, 14.17.5, 16.6.2 or later.");

  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/aug-2021-security-releases/");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/release/v16.6.2/");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/release/v14.17.5/");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/release/v12.22.5/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "12.0", test_version2: "12.22.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12.22.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "14.0", test_version2: "14.17.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.17.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "16.0", test_version2: "16.6.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "16.6.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
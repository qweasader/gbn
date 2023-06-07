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

CPE = "cpe:/a:apache:http_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147044");
  script_version("2021-11-01T14:03:43+0000");
  script_tag(name:"last_modification", value:"2021-11-01 14:03:43 +0000 (Mon, 01 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-01 02:44:54 +0000 (Mon, 01 Nov 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-06 11:15:00 +0000 (Sun, 06 Jun 2021)");

  script_cve_id("CVE-2016-4975");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache HTTP Server CRLF Injection Vulnerability (Dec 2016) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_http_server_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/http_server/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Apache HTTP Server is prone to a CRLF injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Possible CRLF injection allowing HTTP response splitting
  attacks for sites which use mod_userdir. This issue was mitigated to prohibit CR or LF injection
  into the 'Location' or other outbound header key or value.");

  script_tag(name:"affected", value:"Apache HTTP Server version 2.2.0 through 2.2.31 and 2.4.1
  through 2.4.23.");

  script_tag(name:"solution", value:"Update to version 2.2.32, 2.4.25 or later.");

  script_xref(name:"URL", value:"https://httpd.apache.org/security/vulnerabilities_22.html");
  script_xref(name:"URL", value:"https://httpd.apache.org/security/vulnerabilities_24.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE, version_regex: "^[0-9]+\.[0-9]+\.[0-9]+"))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "2.2.0", test_version2: "2.2.31")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.2.32", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "2.4.1", test_version2: "2.4.23")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.4.25", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

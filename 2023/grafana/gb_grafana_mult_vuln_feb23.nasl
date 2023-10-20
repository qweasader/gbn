# Copyright (C) 2023 Greenbone Networks GmbH
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

CPE = "cpe:/a:grafana:grafana";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149399");
  script_version("2023-10-13T05:06:10+0000");
  script_tag(name:"last_modification", value:"2023-10-13 05:06:10 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-03-02 06:50:31 +0000 (Thu, 02 Mar 2023)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-09 00:55:00 +0000 (Thu, 09 Mar 2023)");

  script_cve_id("CVE-2023-0507", "CVE-2023-0594");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Grafana < 8.5.21, 9.2.x < 9.2.13, 9.3.x < 9.3.8 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_grafana_http_detect.nasl");
  script_mandatory_keys("grafana/detected");

  script_tag(name:"summary", value:"Grafana is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-0507: Stored XSS in geomap panel plugin via attribution

  - CVE-2023-0594: Stored XSS in TraceView panel");

  script_tag(name:"affected", value:"Grafana prior to version 8.5.21, version 9.2.0 through 9.2.12
  and 9.3.0 through 9.3.7.");

  script_tag(name:"solution", value:"Update to version 8.5.21, 9.2.13, 9.3.8 or later.");

  script_xref(name:"URL", value:"https://grafana.com/blog/2023/02/28/grafana-security-release-new-versions-with-security-fixes-for-cve-2023-0594-cve-2023-0507-and-cve-2023-22462/");

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

if (version_is_less(version: version, test_version: "8.5.21")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.21", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.2.0", test_version_up: "9.2.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.2.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.3.0", test_version_up: "9.3.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.3.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

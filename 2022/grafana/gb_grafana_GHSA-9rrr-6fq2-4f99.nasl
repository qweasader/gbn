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

CPE = "cpe:/a:grafana:grafana";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148162");
  script_version("2022-06-03T10:57:19+0000");
  script_tag(name:"last_modification", value:"2022-06-03 10:57:19 +0000 (Fri, 03 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-05-23 04:36:38 +0000 (Mon, 23 May 2022)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-02 18:35:00 +0000 (Thu, 02 Jun 2022)");

  script_cve_id("CVE-2022-29170");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Grafana Datasource Network Restriction Bypass Vulnerability (GHSA-9rrr-6fq2-4f99)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_grafana_http_detect.nasl");
  script_mandatory_keys("grafana/detected");

  script_tag(name:"summary", value:"Grafana is prone to a datasource network restriction bypass
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"In Grafana Enterprise, 'Request security allow list' allows to
  configure Grafana in a way so that the instance doesn't call or only calls specific hosts.

  The vulnerability allows to bypass these security configurations if a malicious datasource
  (running on an allowed host) returns an HTTP redirect to a forbidden host.");

  script_tag(name:"impact", value:"The vulnerability is only impacting Grafana Enterprise when the
  'Request security allow list' is used and there is a possibility to add a custom datasource to
  Grafana which returns HTTP redirects. In this scenario, Grafana would blindly follow the
  redirects and potentially give secure information to the clients.");

  script_tag(name:"affected", value:"Grafana version 7.4.x through 7.5.15 and 8.x through 8.5.2.");

  script_tag(name:"solution", value:"Update to version 7.5.16, 8.5.3 or later.");

  script_xref(name:"URL", value:"https://github.com/grafana/grafana/security/advisories/GHSA-9rrr-6fq2-4f99");

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

if (version_in_range_exclusive(version: version, test_version_lo: "7.4.0", test_version_up: "7.5.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.5.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.0", test_version_up: "8.5.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

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

CPE = "cpe:/a:elastic:kibana";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117969");
  script_version("2022-02-24T03:03:30+0000");
  script_tag(name:"last_modification", value:"2022-02-24 03:03:30 +0000 (Thu, 24 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-09 07:20:19 +0000 (Wed, 09 Feb 2022)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-22 13:36:00 +0000 (Tue, 22 Feb 2022)");

  script_cve_id("CVE-2022-23707");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Elastic Kibana XSS Vulnerability (ESA-2022-01)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_elastic_kibana_detect_http.nasl");
  script_mandatory_keys("elastic/kibana/detected");

  script_tag(name:"summary", value:"Elastic Kibana is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An XSS vulnerability was found in Kibana index patterns. Using
  this vulnerability, an authenticated user could bypass Kibana's CSP to inject malicious javascript
  which could fire against a higher-level user.");

  script_tag(name:"affected", value:"Elastic Kibana version 7.5.1 through 7.16.3.");

  script_tag(name:"solution", value:"Update to version 7.17.0 or later.");

  script_xref(name:"URL", value:"https://discuss.elastic.co/t/kibana-7-17-0-security-update/296215");

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

if (version_in_range(version: version, test_version: "7.5.1", test_version2: "7.16.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.17.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

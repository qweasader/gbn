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

CPE = "cpe:/a:elastic:elasticsearch";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144431");
  script_version("2021-07-07T11:00:41+0000");
  script_tag(name:"last_modification", value:"2021-07-07 11:00:41 +0000 (Wed, 07 Jul 2021)");
  script_tag(name:"creation_date", value:"2020-08-20 02:58:20 +0000 (Thu, 20 Aug 2020)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-27 11:15:00 +0000 (Thu, 27 Aug 2020)");

  script_cve_id("CVE-2020-7019");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Elastic Elasticsearch < 6.8.12, 7.x < 7.9.0 Information Disclosure Vulnerability (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_elastic_elasticsearch_detect_http.nasl", "os_detection.nasl");
  script_mandatory_keys("elastic/elasticsearch/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Elasticsearch is prone to a field disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A field disclosure flaw was found in Elasticsearch when running a scrolling
  search with Field Level Security. If a user runs the same query another more privileged user recently ran, the
  scrolling search can leak fields that should be hidden.");

  script_tag(name:"impact", value:"An attacker could gain additional permissions against a restricted index.");

  script_tag(name:"affected", value:"Elasticsearch prior to version 6.8.12 and 7.9.0.");

  script_tag(name:"solution", value:"Update to version 6.8.12, 7.9.1 or later.");

  script_xref(name:"URL", value:"https://discuss.elastic.co/t/elastic-stack-7-9-0-and-6-8-12-security-update/245456");

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

if (version_is_less(version: version, test_version: "6.8.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.8.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version =~ "^7\." && version_is_less(version: version, test_version: "7.9.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.9.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

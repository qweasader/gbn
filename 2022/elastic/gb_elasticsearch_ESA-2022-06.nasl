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

CPE = "cpe:/a:elastic:elasticsearch";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148222");
  script_version("2022-06-08T03:04:00+0000");
  script_tag(name:"last_modification", value:"2022-06-08 03:04:00 +0000 (Wed, 08 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-06-07 06:45:38 +0000 (Tue, 07 Jun 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-29 03:15:00 +0000 (Fri, 29 Apr 2022)");

  script_cve_id("CVE-2022-21449");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # Depending on the installed JDK

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Elastic Elasticsearch Java Vulnerability (ESA-2022-06)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_elastic_elasticsearch_detect_http.nasl");
  script_mandatory_keys("elastic/elasticsearch/detected");

  script_tag(name:"summary", value:"Elastic Elasticsearch is prone to a vulnerability in Java.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability affecting the implementation of Elliptic Curve
  Digital Signing Algorithm (ECDSA) based signatures verification in Java JDK versions 15 and later
  was published on April 19, 2022. This vulnerability affects Oracle Java and OpenJDK, including
  other JDKs derived from OpenJDK.");

  script_tag(name:"affected", value:"Elastic Elasticsearch version 6.8.x and 7.9.2 and later.");

  script_tag(name:"solution", value:"Update to version 7.17.4, 8.2.1 or later.");

  script_xref(name:"URL", value:"https://discuss.elastic.co/t/elastic-stack-7-17-1-security-update/298447");

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

if (version =~ "^6\.8\." ||
    version_in_range_exclusive(version: version, test_version_lo: "7.9.2", test_version_up: "7.17.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.17.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.0.0", test_version2: "8.2.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.2.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

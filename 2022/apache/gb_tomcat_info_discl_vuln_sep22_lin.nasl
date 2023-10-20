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

CPE = "cpe:/a:apache:tomcat";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148785");
  script_version("2023-10-18T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-10-18 05:05:17 +0000 (Wed, 18 Oct 2023)");
  script_tag(name:"creation_date", value:"2022-09-29 06:16:47 +0000 (Thu, 29 Sep 2022)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-05 17:12:00 +0000 (Wed, 05 Oct 2022)");

  script_cve_id("CVE-2021-43980");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat Information Disclosure Vulnerability (Sep 2022) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Apache Tomcat is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The simplified implementation of blocking reads and writes
  introduced in Tomcat 10 and back-ported to Tomcat 9.0.47 onwards exposed a long standing (but
  extremely hard to trigger) concurrency bug that could cause client connections to share an
  Http11Processor instance resulting in responses, or part responses, to be received by the wrong
  client.");

  script_tag(name:"affected", value:"Apache Tomcat version 8.5.0 through 8.5.77, 9.0.0-M1 through
  9.0.60, 10.0.0-M1 through 10.0.18 and 10.1.0-M1 through 10.1.0-M12.");

  script_tag(name:"solution", value:"Update to version 8.5.78, 9.0.62, 10.0.20, 10.1.0-M14 or
  later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/3jjqbsp6j88b198x5rmg99b1qr8ht3g3");

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

if (version_in_range(version: version, test_version: "8.5.0", test_version2: "8.5.77")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.78", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.0.0.M1", test_version2: "9.0.60")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.62", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.0.0.M1", test_version2: "10.0.18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.0.20", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.1.0.M1", test_version2: "10.1.0.M12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.1.0-M14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

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

CPE = "cpe:/a:apache:tomcat";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146895");
  script_version("2021-10-13T11:49:52+0000");
  script_tag(name:"last_modification", value:"2021-10-13 11:49:52 +0000 (Wed, 13 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-10-13 11:45:47 +0000 (Wed, 13 Oct 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2014-0050");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat DoS Vulnerability (Apr 2014) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Apache Tomcat is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"insight", value:"MultipartStream.java in Apache Commons FileUpload before 1.3.1,
  as used in Apache Tomcat, allows remote attackers to cause a denial of service (infinite loop and
  CPU consumption) via a crafted Content-Type header that bypasses a loop's intended exit conditions.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Apache Tomcat version 7.x through 7.0.50 and 8.x through 8.0.1.");

  script_tag(name:"solution", value:"Update to version 7.0.52, 8.0.3 or later.");

  script_xref(name:"URL", value:"https://tomcat.apache.org/security-7.html");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-8.html");

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

if (version_in_range(version: version, test_version: "7.0", test_version2: "7.0.50")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.52", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.0", test_version2: "8.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

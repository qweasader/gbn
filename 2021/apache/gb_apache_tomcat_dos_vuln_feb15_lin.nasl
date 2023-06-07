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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146893");
  script_version("2021-10-13T11:49:52+0000");
  script_tag(name:"last_modification", value:"2021-10-13 11:49:52 +0000 (Wed, 13 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-10-13 09:55:23 +0000 (Wed, 13 Oct 2021)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");

  script_cve_id("CVE-2014-0227");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat DoS Vulnerability (Mar 2015) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Apache Tomcat is prone to denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to ChunkedInputFilter implementation in Apache
  Tomcat did not fail subsequent attempts to read input after a failure occurred.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to perform a
  denial of service attack by streaming an unlimited quantity of data, leading to excessive
  consumption of system resources.");

  script_tag(name:"affected", value:"Apache Tomcat 6.x before 6.0.42, 7.x before 7.0.55, and 8.x
  before 8.0.9.");

  script_tag(name:"solution", value:"Update to version 6.0.42, 7.0.55, 8.0.9 or later.");

  script_xref(name:"URL", value:"http://tomcat.apache.org/security-8.html");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-7.html");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-6.html");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2015-02/0067.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if (version_in_range(version:version, test_version:"6.0", test_version2:"6.0.41"))
  fix = "6.0.42";

if (version_in_range(version:version, test_version:"7.0", test_version2:"7.0.54"))
  fix = "7.0.55";

if (version_in_range(version:version, test_version:"8.0", test_version2:"8.0.8"))
  fix = "8.0.9";

if (fix) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

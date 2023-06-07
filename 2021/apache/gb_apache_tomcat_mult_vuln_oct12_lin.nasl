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
  script_oid("1.3.6.1.4.1.25623.1.0.147033");
  script_version("2021-10-29T11:49:32+0000");
  script_tag(name:"last_modification", value:"2021-10-29 11:49:32 +0000 (Fri, 29 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-10-29 10:16:48 +0000 (Fri, 29 Oct 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2012-4431", "CVE-2012-2733", "CVE-2012-4534", "CVE-2012-3439",
                "CVE-2012-3546");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat 6.x < 6.0.36 Multiple Vulnerabilities (Oct 2012) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Apache Tomcat is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2012-4431: The CSRF prevention filter could be bypassed if a request was made to a
  protected resource without a session identifier present in the request.

  - CVE-2012-2733: The checks that limited the permitted size of request headers were implemented
  too late in the request parsing process for the HTTP NIO connector. This enabled a malicious user
  to trigger an OutOfMemoryError by sending a single request with very large headers.

  - CVE-2012-4534: When using the NIO connector with sendfile and HTTPS enabled, if a client breaks
  the connection while reading the response an infinite loop is entered leading to a denial of
  service.

  - CVE-2012-3439: DIGEST authentication weakness

  - CVE-2012-3546: When using FORM authentication it was possible to bypass the security constraint
  checks in the FORM authenticator by appending /j_security_check to the end of the URL if some
  other component (such as the Single-Sign-On valve) had called request.setUserPrincipal() before
  the call to FormAuthenticator#authenticate().");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Apache Tomcat version 6.0.x through 6.0.35.");

  script_tag(name:"solution", value:"Update to version 6.0.36 or later.");

  script_xref(name:"URL", value:"https://tomcat.apache.org/security-6.html");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "6.0.0", test_version2: "6.0.35")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.36", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

# Copyright (C) 2017 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811214");
  script_version("2022-04-13T11:57:07+0000");
  script_cve_id("CVE-2017-7679", "CVE-2017-3169", "CVE-2017-3167");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-06 11:15:00 +0000 (Sun, 06 Jun 2021)");
  script_tag(name:"creation_date", value:"2017-06-21 17:25:22 +0530 (Wed, 21 Jun 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Apache HTTP Server Multiple Vulnerabilities June17 (Linux)");

  script_tag(name:"summary", value:"Apache HTTP Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist as,

  - The mod_mime can read one byte past the end of a buffer when sending a malicious
    Content-Type response header.

  - The mod_ssl may dereference a NULL pointer when third-party modules call
    ap_hook_process_connection() during an HTTP request to an HTTPS port.

  - An use of the ap_get_basic_auth_pw() by third-party modules outside of the
    authentication phase may lead to authentication requirements being
    bypassed.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass authentication and perform unauthorized actions, cause
  a denial-of-service condition and gain access to potentially sensitive
  information.");

  script_tag(name:"affected", value:"Apache HTTP Server 2.2.x before 2.2.33 and
  2.4.x before 2.4.26.");

  script_tag(name:"solution", value:"Update to Apache HTTP Server 2.2.33 or 2.4.26
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2017/q2/509");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99135");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99134");
  script_xref(name:"URL", value:"http://httpd.apache.org/security/vulnerabilities_24.html");
  script_xref(name:"URL", value:"http://httpd.apache.org/security/vulnerabilities_22.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_http_server_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/http_server/detected", "Host/runs_unixoide");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE, version_regex:"^[0-9]+\.[0-9]+\.[0-9]+"))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^2\.4") {
  if(version_is_less(version:vers, test_version:"2.4.26")) {
    fix = "2.4.26";
  }
}
else if(vers =~ "^2\.2") {
  if(version_is_less(version:vers, test_version:"2.2.33")) {
    fix = "2.2.33";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
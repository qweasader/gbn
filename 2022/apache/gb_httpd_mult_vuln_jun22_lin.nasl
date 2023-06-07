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

CPE = "cpe:/a:apache:http_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148252");
  script_version("2022-06-20T03:04:15+0000");
  script_tag(name:"last_modification", value:"2022-06-20 03:04:15 +0000 (Mon, 20 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-06-10 04:36:50 +0000 (Fri, 10 Jun 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-17 19:19:00 +0000 (Fri, 17 Jun 2022)");

  script_cve_id("CVE-2022-26377", "CVE-2022-28614", "CVE-2022-28615", "CVE-2022-29404",
                "CVE-2022-30556", "CVE-2022-31813");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache HTTP Server < 2.4.54 Multiple Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_http_server_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/http_server/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Apache HTTP Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-26377: mod_proxy_ajp: Possible request smuggling

  - CVE-2022-28614: Read beyond bounds via ap_rwrite()

  - CVE-2022-28615: Read beyond bounds in ap_strcmp_match()

  - CVE-2022-29404: Denial of service in mod_lua r:parsebody

  - CVE-2022-30556: Information disclosure in mod_lua with websockets

  - CVE-2022-31813: mod_proxy X-Forwarded-For dropped by hop-by-hop mechanism");

  script_tag(name:"affected", value:"Apache HTTP Server version 2.4.53 and prior.");

  script_tag(name:"solution", value:"Update to version 2.4.54 or later.");

  script_xref(name:"URL", value:"https://httpd.apache.org/security/vulnerabilities_24.html#2.4.54");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE,
                                          version_regex: "^[0-9]+\.[0-9]+\.[0-9]+"))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "2.4.54")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.4.54", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

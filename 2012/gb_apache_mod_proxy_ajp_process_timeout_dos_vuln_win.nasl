# Copyright (C) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.802683");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2012-4557");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-12-06 18:00:42 +0530 (Thu, 06 Dec 2012)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Apache HTTP Server mod_proxy_ajp Process Timeout DoS Vulnerability (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_http_server_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/http_server/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=871685");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56753");
  script_xref(name:"URL", value:"http://httpd.apache.org/security/vulnerabilities_22.html#2.2.22");
  script_xref(name:"URL", value:"http://svn.apache.org/viewvc?view=revision&revision=1227298");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to cause a denial of
  service condition via an expensive request.");

  script_tag(name:"affected", value:"Apache HTTP Server version 2.2.12 through 2.2.21.");

  script_tag(name:"insight", value:"The flaw is due to an error in the mod_proxy_ajp module, which places a worker
  node into an error state upon detection of a long request-processing time.");

  script_tag(name:"summary", value:"Apache HTTP Server is prone to a denial of service vulnerability.");

  script_tag(name:"solution", value:"Update to Apache HTTP Server 2.2.22 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

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

if(version_in_range(version:vers, test_version:"2.2.12", test_version2:"2.2.21")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"2.2.22", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

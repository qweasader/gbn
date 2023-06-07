# Copyright (C) 2011 Greenbone Networks GmbH
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

CPE = "cpe:/a:sitracker:support_incident_tracker";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103257");
  script_version("2022-05-25T13:03:27+0000");
  script_tag(name:"last_modification", value:"2022-05-25 13:03:27 +0000 (Wed, 25 May 2022)");
  script_tag(name:"creation_date", value:"2011-09-15 12:51:05 +0200 (Thu, 15 Sep 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Support Incident Tracker (SiT!) < 3.65 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_support_incident_tracker_http_detect.nasl");
  script_mandatory_keys("sit/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Support Incident Tracker (SiT!) is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following input validation vulnerabilities exist:

  - Multiple cross-site scripting (XSS)

  - Multiple SQL injection (SQLi)

  - Multiple cross-site request forgery (CSRF)");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Exploiting these issues could allow an attacker to execute
  arbitrary code, steal cookie-based authentication credentials, compromise the application, access
  or modify data, or exploit latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"Support Incident Tracker (SiT!) version 3.64 and prior.");

  script_tag(name:"solution", value:"Update to version 3.65 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49623");
  script_xref(name:"URL", value:"https://www.htbridge.ch/advisory/multiple_vulnerabilities_in_sit_support_incident_tracker.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/519636");
  script_xref(name:"URL", value:"http://sitracker.org/wiki/ReleaseNotes365");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/portal/kb.php?start=%27";

if (http_vuln_check(port: port, url: url, pattern: "You have an error in your SQL syntax")) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

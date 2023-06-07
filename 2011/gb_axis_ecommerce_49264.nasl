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

CPE = "cpe:/a:axiscommerce:axiscommerce";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103224");
  script_version("2022-09-16T10:11:41+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:41 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"creation_date", value:"2011-08-24 15:44:33 +0200 (Wed, 24 Aug 2011)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Axis Commerce <= 0.8.1 XSS Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_axis_commerce_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("axis_ecommerce/http/detected");

  script_tag(name:"summary", value:"Axis Commerce is prone to a cross-site scripting (XSS)
  vulnerability because it fails to sufficiently sanitize user-supplied data.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Attacker-supplied HTML and script code would run in the context
  of the affected browser, potentially allowing the attacker to steal cookie-based authentication
  credentials or control how the site is rendered to the user.");

  script_tag(name:"affected", value:"Axis Commerce version 0.8.1 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49264");

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

url = dir + "/search/result?q=%22%3E%3Cscript%3Ealert(%27vt-xss-test%27)%3C/script%3E";

if (http_vuln_check(port: port, url: url, pattern: "<script>alert\('vt-xss-test'\)</script>",
                    check_header: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

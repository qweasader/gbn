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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802390");
  script_version("2023-02-24T10:20:04+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-02-24 10:20:04 +0000 (Fri, 24 Feb 2023)");
  script_tag(name:"creation_date", value:"2012-02-02 14:49:35 +0530 (Thu, 02 Feb 2012)");

  script_cve_id("CVE-2012-1005");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Sphinx Mobile Web Server <= 3.1.2.47 Multiple XSS Vulnerabilities - Active Check");

  script_category(ACT_DESTRUCTIVE_ATTACK); # Stored XSS

  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("MobileWebServer/banner");

  script_tag(name:"summary", value:"Sphinx Mobile Web Server is prone to persistent cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaws are due to an improper validation of user-supplied
  input via the 'comment' parameter to '/Blog/MyFirstBlog.txt' and '/Blog/AboutSomething.txt',
  which allows attacker to execute arbitrary HTML and script code on the user's browser session in
  the security context of an affected site.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser session in the context
  of an affected site.");

  script_tag(name:"affected", value:"Sphinx Mobile Web Server U3 3.1.2.47 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://secpod.org/blog/?p=453");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51820");
  script_xref(name:"URL", value:"http://secunia.com/advisories/47876");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/72913");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18451/");
  script_xref(name:"URL", value:"http://secpod.org/advisories/SecPod_SPHINX_SOFT_Mobile_Web_Server_Mul_Persistence_XSS_Vulns.txt");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 8080);

banner = http_get_remote_headers(port: port);
if ("Server: MobileWebServer/" >!< banner)
  exit(0);

pages = make_list("/MyFirstBlog.txt", "/AboutSomething.txt");

foreach page (pages) {
  url = "/Blog" + page + "?comment=<script>alert(document.cookie)</script>&submit=Add+Comment";

  req = http_get(port: port, item: url);
  http_keepalive_send_recv(port: port, data: req);

  url = "/Blog" + page;

  if (http_vuln_check(port: port, url: url, pattern:"<script>alert\(document.cookie\)</script>",
                      check_header: TRUE)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);

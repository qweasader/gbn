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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902526");
  script_version("2022-12-05T10:11:03+0000");
  script_tag(name:"last_modification", value:"2022-12-05 10:11:03 +0000 (Mon, 05 Dec 2022)");
  script_tag(name:"creation_date", value:"2011-06-24 16:31:03 +0200 (Fri, 24 Jun 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Oracle HTTP Server 'Expect' Header Cross-Site Scripting Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_oracle_app_server_detect.nasl");
  script_mandatory_keys("oracle/http_server/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site.");

  script_tag(name:"affected", value:"Oracle HTTP Server for Oracle Application Server 10g Release 2.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input passed via
  the 'Expect' header from an HTTP request, which allows attackers to execute
  arbitrary HTML and script code on the web server.");

  script_tag(name:"solution", value:"Upgrade to Oracle HTTP Server 11g or later.");

  script_tag(name:"summary", value:"Oracle HTTP Server is prone to a cross-site scripting (XSS) vulnerability.");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17393/");
  script_xref(name:"URL", value:"http://www.securiteam.com/securityreviews/5KP0M1FJ5E.html");
  script_xref(name:"URL", value:"http://www.yaboukir.com/wp-content/bugtraq/XSS_Header_Injection_in_OHS_by_Yasser.pdf");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

CPE = "cpe:/a:oracle:http_server";

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!get_app_location(port:port, cpe:CPE, nofork:TRUE))
  exit(0);

host = http_host_name(port:port);

url = "/index.html";
req = string("GET ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "Expect: <script>alert('vt-xss-test')</script>\r\n\r\n");
res = http_keepalive_send_recv(port:port, data:req);

if(res =~ "^HTTP/1\.[01] 200" && "Expect: <script>alert('vt-xss-test')</script>" >< res) {
  report  = http_report_vuln_url(port:port, url:url);
  report += '\nAffected header: "Expect"';
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

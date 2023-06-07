# Copyright (C) 2018 Greenbone Networks GmbH
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

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814021");
  script_version("2022-12-05T10:11:03+0000");
  script_cve_id("CVE-2018-17082");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-12-05 10:11:03 +0000 (Mon, 05 Dec 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-19 11:15:00 +0000 (Mon, 19 Aug 2019)");
  script_tag(name:"creation_date", value:"2018-09-18 12:42:13 +0530 (Tue, 18 Sep 2018)");
  script_name("PHP 'Transfer-Encoding: chunked' XSS Vulnerability");

  script_tag(name:"summary", value:"PHP is prone to a Cross-Site Scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and confirms the
  vulnerability from the response.");

  script_tag(name:"insight", value:"The flaw is due to the bucket brigade is mishandled in the
  php_handler function in 'sapi/apache2handler/sapi_apache2.c' script.");

  script_tag(name:"impact", value:"Successful exploitation allows a remote attacker to execute
  arbitrary script code in the browser of an unsuspecting user in the context of the affected site.
  This may allow the attacker to steal cookie-based authentication credentials and to launch
  other attacks.");

  script_tag(name:"affected", value:"'sapi/apache2handler/sapi_apache2.c' component in PHP before
  5.6.38, 7.0.x before 7.0.32, 7.1.x before 7.1.22, and 7.2.x before 7.2.10.");

  script_tag(name:"solution", value:"Update to PHP 5.6.38, 7.2.10, 7.1.22 or later. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_probe");
  script_xref(name:"URL", value:"http://php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://php.net/ChangeLog-7.php");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=76582");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_php_http_detect.nasl", "secpod_apache_http_server_http_detect.nasl");
  script_mandatory_keys("php/detected", "apache/http_server/http/detected");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("misc_func.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

url = "/index.php";
data = "<script>alert(document.cookie)</script>";

req = http_post_put_req(port:port,
                        url:url,
                        data:data,
                        add_headers:make_array("Transfer-Encoding", "chunked"));
res = http_send_recv(port:port, data:req);

if(res =~ "^HTTP/1\.[01] 200" && "<script>alert(document.cookie)</script>" >< res) {
  report = http_report_vuln_url(port:port, url:url);
  report += '\nHeader:    "Transfer-Encoding: chunked"';
  report += '\nPOST-Data: ' + data;
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

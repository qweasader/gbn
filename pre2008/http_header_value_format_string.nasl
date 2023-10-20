# SPDX-FileCopyrightText: 2004 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15642");
  script_version("2023-06-22T10:34:15+0000");
  script_tag(name:"last_modification", value:"2023-06-22 10:34:15 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Format string on HTTP header value");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("Copyright (C) 2004 Michel Arboi");
  script_family("Gain a shell remotely");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The remote web server seems to be vulnerable to a format string attack
  on HTTP 1.0 header value.");

  script_tag(name:"impact", value:"An attacker might use this flaw to make it crash or even execute
  arbitrary code on this host.");

  script_tag(name:"solution", value:"Upgrade your software or contact your vendor and inform him
  of this vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_probe");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("global_settings.inc");
include("misc_func.inc");

port = http_get_port( default:80 );
if( http_is_dead( port:port ) ) exit( 0 );

vt_strings = get_vt_strings();

req = http_get( item:strcat( "/", vt_strings["lowercase_rand"], ".html" ), port:port );
soc = http_open_socket( port );
if( ! soc ) exit( 0 );
send( socket:soc, data:req );
r = http_recv( socket:soc );
http_close_socket( soc );

flag  = 0;
flag2 = 0;

if( egrep( pattern:"[0-9a-fA-F]{8}", string:r ) ) {
  flag = 1;
  debug_print( 'Normal answer:\n', r );
}

foreach header( make_list(
  # HTTP/1.0
  "From", "If-Modified-Since", "Referer", "Content-Length", "Content-Type",
  # HTTP/1.1
  "Host", "Accept-Encoding", "Accept-Language", "Accept-Range", "Connection",
  "Expect", "If-Match", "If-None-Match", "If-Range", "If-Unmodified-Since",
  "Max-Forwards", "TE" ) ) {

  foreach bad( make_list( "%08x", "%s", "%#0123456x%08x%x%s%p%n%d%o%u%c%h%l%q%j%z%Z%t%i%e%g%f%a%C%S%08x%%#0123456x%%x%%s%%p%%n%%d%%o%%u%%c%%h%%l%%q%%j%%z%%Z%%t%%i%%e%%g%%f%%a%%C%%S%%08x" ) ) {

    soc = http_open_socket( port );
    if( ! soc )
      continue;

    req2 = ereg_replace( string:req, icase:TRUE, pattern:strcat( header, ':[\r\n]*\r\n' ), replace:strcat( header, ': ', bad, '\r\n' ) );
    if( req2 == req )
      req2 = ereg_replace( string:req, pattern:'(GET[^\r\n]*\r\n)', replace:strcat("\1", header, ': ', bad, '\r\n' ) );

    debug_print( "Request: \n", req2 );

    send( socket:soc, data:req2 );
    r = http_recv( socket:soc );
    http_close_socket( soc );
    if( egrep( pattern:"[0-9a-fA-F]{8}", string:r ) && r !~ "^HTTP/1\.[01] 404" ) {
      debug_print( 'Format string:\n', r );
      flag2++;
    }
  }

  if( http_is_dead( port:port ) ) {
    security_message( port:port );
    exit( 0 );
  }

  if( flag2 && ! flag ) {
    security_message( port:port );
    exit( 0 );
  }
}

exit( 99 );

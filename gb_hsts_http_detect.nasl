# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105876");
  script_version("2024-09-27T05:05:23+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-09-27 05:05:23 +0000 (Fri, 27 Sep 2024)");
  script_tag(name:"creation_date", value:"2016-08-22 13:07:41 +0200 (Mon, 22 Aug 2016)");
  script_name("SSL/TLS: HTTP Strict Transport Security (HSTS) Detection");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  # nb: Don't add a dependency to e.g. webmirror.nasl or DDI_Directory_Scanner.nasl
  # to allow a minimal SSL/TLS check configuration.
  script_dependencies("find_service.nasl", "httpver.nasl", "gb_ssl_tls_version_get.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("ssl_tls/port");

  script_xref(name:"URL", value:"https://owasp.org/www-project-secure-headers/");
  script_xref(name:"URL", value:"https://owasp.org/www-project-cheat-sheets/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html");
  script_xref(name:"URL", value:"https://owasp.org/www-project-secure-headers/#http-strict-transport-security-hsts");
  script_xref(name:"URL", value:"https://tools.ietf.org/html/rfc6797");
  script_xref(name:"URL", value:"https://securityheaders.io/");

  script_tag(name:"summary", value:"Checks if the remote web server has HTTP Strict Transport
  Security (HSTS) enabled.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port( default:443, ignore_cgi_disabled:TRUE );
if( get_port_transport( port ) < ENCAPS_SSLv23 )
  exit( 0 );

banner = http_get_remote_headers( port:port );
if( ! banner || banner !~ "^HTTP/1\.[01] [0-9]{3}" )
  exit( 0 );

if( ! sts = egrep( pattern:"^Strict-Transport-Security\s*:", string:banner, icase:TRUE ) ) { # Header fields are case-insensitive: https://tools.ietf.org/html/rfc7230#section-3.2
  # The 304 status code has a special meaning and shouldn't contain any additional headers -> https://tools.ietf.org/html/rfc2616#section-10.3.5
  # e.g. mod_headers from Apache won't add additional headers on this code so don't complain about a missing header.
  # nb: There might be still some web servers sending the headers on a 304 status code so we're still reporting it below if there was a header included.
  if( banner !~ "^HTTP/1\.[01] 304" ) {
    set_kb_item( name:"hsts/missing", value:TRUE );
    set_kb_item( name:"hsts/missing/port", value:port );
  }
  exit( 0 );
}

sts = chomp( sts );
sts_lo = tolower( sts );

# max-age is required: https://tools.ietf.org/html/rfc6797#page-16
# Assume a missing HSTS if its not specified
if( "max-age=" >!< sts_lo ) {
  set_kb_item( name:"hsts/missing", value:TRUE );
  set_kb_item( name:"hsts/missing/port", value:port );
  set_kb_item( name:"hsts/max_age/missing/" + port, value:TRUE );
  set_kb_item( name:"hsts/" + port + "/banner", value:sts );
  exit( 0 );
}

# From https://tools.ietf.org/html/rfc6797#page-16:
# A max-age value of zero (i.e., "max-age=0") signals the UA to
# cease regarding the host as a Known HSTS Host
if( "max-age=0" >< sts_lo ) {
  set_kb_item( name:"hsts/missing", value:TRUE );
  set_kb_item( name:"hsts/missing/port", value:port );
  set_kb_item( name:"hsts/max_age/zero/" + port, value:TRUE );
  set_kb_item( name:"hsts/" + port + "/banner", value:sts );
  exit( 0 );
}

set_kb_item( name:"hsts/available", value:TRUE );
set_kb_item( name:"hsts/available/port", value:port );
set_kb_item( name:"hsts/" + port + "/banner", value:sts );

if( "includesubdomains" >!< sts_lo ) {
  set_kb_item( name:"hsts/includeSubDomains/missing", value:TRUE );
  set_kb_item( name:"hsts/includeSubDomains/missing/port", value:port );
}

if( "preload" >!< sts_lo ) {
  set_kb_item( name:"hsts/preload/missing", value:TRUE );
  set_kb_item( name:"hsts/preload/missing/port", value:port );
}

ma = eregmatch( pattern:"max-age=([0-9]+)", string:sts, icase:TRUE );

if( ! isnull( ma[1] ) )
  set_kb_item( name:"hsts/max_age/" + port, value:ma[1] );

log_message( port:port, data:'The remote web server is sending the "HTTP Strict-Transport-Security" header.\n\nHSTS-Header:\n\n' + sts );

exit( 0 );

# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108531");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2019-01-20 14:05:39 +0100 (Sun, 20 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Adminer Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80); # nb: TurnKeyLAMP might also run on 12322
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.adminer.org/");

  script_tag(name:"summary", value:"HTTP based detection of Adminer.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");
include("cpe.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) )
  exit( 0 );

rootInstalled = FALSE;

foreach dir( make_list_unique( "/", "/adminer", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  if( rootInstalled )
    break;

  url  = dir + "/adminer.php";
  buf  = http_get_cache( item:url, port:port );

  url2 = dir + "/";
  buf2 = http_get_cache( item:url2, port:port );

  if( ( buf =~ "^HTTP/1\.[01] 200" || buf2 =~ "^HTTP/1\.[01] 200" ) &&
      ( "<title>Login - Adminer</title>" >< buf ||
        "<title>Login - Adminer</title>" >< buf2 ||
        ( "://www.adminer.org/'" >< buf && "id='h1'>Adminer</a>" >< buf ) ||
        ( "://www.adminer.org/'" >< buf2 && "id='h1'>Adminer</a>" >< buf2 ) ) ) {

    version = "unknown";
    conclUrl = http_report_vuln_url( port:port, url:url2, url_only:TRUE );
    if( install == "/" )
      rootInstalled = TRUE;

    # onload: partial(verifyVersion, '4.7.0', '?', '674453:67503')});
    # id='h1'>Adminer</a> <span class="version">4.7.0</span>
    #
    # onclick="bodyClick(event);" onload="verifyVersion('4.2.5');">
    # id='h1'>Adminer</a> <span class="version">4.2.5</span>

    vers = eregmatch( pattern:"verifyVersion(, '|\(')([^']+)'", string:buf, icase:FALSE );
    if( vers[2] ) {
      version = vers[2];
      conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    }

    if( version == "unknown" ) {
      vers = eregmatch( pattern:"verifyVersion(, '|\(')([^']+)'", string:buf2, icase:FALSE );
      if( vers[2] ) {
        version = vers[2];
        conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
      }
    }

    if( version == "unknown" ) {
      vers = eregmatch( pattern:'class="version">([^<]+)<', string:buf, icase:FALSE );
      if( vers[1] ) {
        version = vers[1];
        conclUrl = http_report_vuln_url( port:port, url:url2, url_only:TRUE );
      }
    }

    if( version == "unknown" ) {
      vers = eregmatch( pattern:'class="version">([^<]+)<', string:buf2, icase:FALSE );
      if( vers[1] ) {
        version = vers[1];
        conclUrl = http_report_vuln_url( port:port, url:url2, url_only:TRUE );
      }
    }

    set_kb_item( name:"www/" + port + "/adminer", value:version );
    set_kb_item( name:"adminer/detected", value:TRUE );
    register_and_report_cpe( app:"Adminer", ver:version, concluded:vers[0], conclUrl:conclUrl, base:"cpe:/a:adminer:adminer:", expr:"^([0-9.]+)", insloc:install, regPort:port, regService:"www" );
  }
}

exit( 0 );

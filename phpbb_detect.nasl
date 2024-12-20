# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100033");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2009-03-10 08:40:52 +0100 (Tue, 10 Mar 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("phpBB Forum Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.phpbb.com/");

  script_tag(name:"summary", value:"This host is running phpBB a widely installed Open Source forum solution.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");
include("version_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) ) exit( 0 );

rootInstalled = 0;

foreach dir( make_list_unique( "/", "/board", "/forum", "/phpbb", "/phpBB", "/phpBB2", "/phpBB3", "/phpBB31", http_cgi_dirs( port:port ) ) ) {

  if( rootInstalled ) break;

  install = dir;
  if( dir == "/" ) dir = "";

  buf = http_get_cache( item:dir + "/index.php", port:port );

  if( buf =~ "^HTTP/1\.[01] 200" && ( egrep( pattern:"^Set-Cookie: phpbb.*", string:buf ) ||
      egrep( pattern:".*Powered.*by.*<[^>]+>phpBB</a>.*", string:buf ) ||
      egrep( pattern:".*The phpBB Group.*: [0-9]{4}", string:buf ) ) ) {

    if( dir == "" ) rootInstalled = 1;
    vers = "unknown";

    url = dir + "/docs/INSTALL.html";
    req = http_get( item:url, port:port );
    buf = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

    if( ! isnull( buf ) ) {
      version = eregmatch( string:buf, pattern:"phpBB-[a-zA-Z0-9.\-]+_to_([a-zA-Z0-9.\-]+).patch" );
      if( ! isnull( version[1] ) ) {
        vers = version[1];
        conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
      } else {
        version = eregmatch( string:buf, pattern:"phpBB-([a-zA-Z0-9.\-]+)-patch.zip/tar.bz2" );
        if( ! isnull( version[1] ) ) {
          vers = version[1];
          conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
        }
      }
    }

    #/docs/INSTALL.html in 3.1.x+ is currently not reliable (3.2.4 has e.g. 3.2.1)
    if( ! version_is_less_equal( version:vers, test_version:"3.1.0" ) ) {

      # Overwriting the not reliable version from the INSTALL.html above
      vers = "unknown";

      url = dir + "/docs/CHANGELOG.html";
      req = http_get( item:url, port:port );
      buf = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

      # Version is always "Changes since 3.1.x + 1" with some special cases handled below.
      version = eregmatch( string:buf, pattern:"Changes since 3.([1-9]).([0-9]+)(-[a-zA-Z]+[0-9]*)?" );
      if( ! isnull( version[1] ) && ! isnull( version[2] ) && ( isnull( version[3] ) || "-PL" >< version[3] ) ) {
        conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
        version[2]++;
        vers = "3." + version[1] + "." + version[2];

      # There are special cases like "Changes since 3.2.4-RC1" or "Changes since 3.2.0-a1"
      # where the actual version is/was 3.2.4/3.2.0. Unfortnately we don't now if the next version
      # was e.g. RC2 or the final release so we assume the next version as the "final" one.
      } else if( ! isnull( version[1] ) && ! isnull( version[2] ) && ! isnull( version[3] ) ) {
        conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
        vers = "3." + version[1] + "." + version[2];
      }

      # Another special handling for "Changes since 3.0.x" or "Changes since 3.1.x"
      if( vers == "unknown" ) {
        version = eregmatch( string:buf, pattern:"Changes since 3.([0-9]).x" );
        if( ! isnull( version[1] ) ) {
          conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
          version[1]++;
          vers = "3." + version[1] + ".0";
        }
      }
    }

    if( vers == "unknown" ) {
      foreach style( make_list( "/styles/prosilver/style.cfg", "/styles/subsilver2/style.cfg" ) ) {
        url = dir + style;
        req = http_get( item:url, port:port );
        buf = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
        version = eregmatch( string:buf, pattern:"version = ([a-zA-Z0-9.\-]+)" );
        if( ! isnull( version[1] ) ) {
          vers = version[1];
          conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
          break;
        }
      }
    }

    set_kb_item( name:"www/can_host_tapatalk", value:TRUE ); # nb: Used in sw_tapatalk_detect.nasl for plugin scheduling optimization
    set_kb_item( name:"phpBB/installed",value:TRUE );
    tmp_version = vers + " under " + install;
    set_kb_item( name:"www/" + port + "/phpBB", value:tmp_version );

    cpe = build_cpe( value:vers, exp:"^([0-9.]+([a-z0-9]+)?)", base:"cpe:/a:phpbb:phpbb:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:phpbb:phpbb';

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"phpBB",
                                              version:vers,
                                              install:install,
                                              cpe:cpe,
                                              concludedUrl:conclUrl,
                                              concluded:version[0] ),
                                              port:port );
  }
}

exit( 0 );

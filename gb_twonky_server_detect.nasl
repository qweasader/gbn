# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108003");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-09-27 12:00:00 +0200 (Tue, 27 Sep 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Twonky Server Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 9000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script sends a HTTP request
  to the server and attempts to extract the version from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");
include("cpe.inc");

port = http_get_port( default:9000 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  if( dir == "/webconfig" )
    continue; # Avoids doubled detection at / and /webconfig if GUI is password protected

  buf = http_get_cache( item:dir + "/", port:port );

  if( "<title>Twonky Server</title>" >< buf ||
      '<div id="twFooter">' >< buf ||
      "<title>TwonkyServer Media Browser</title>" >< buf ||
      # 2004-2011 PacketVideo Corporation. All rights reserved.</div>
      # 2004-2009 PacketVideo&nbsp;Corporation. All&nbsp;rights&nbsp;reserved</div>
      buf =~ "PacketVideo(\s|&nbsp;)Corporation\.(\s|&nbsp;)All(\s|&nbsp;)rights(\s|&nbsp;)reserved" ||
      "<title>TwonkyMedia</title>" >< buf ||
      "<title>TwonkyServer</title>" >< buf ||
      '<script type="text/javascript" src="http://profile.twonky.com/tsconfig/js/onlinesvcs.js" defer="defer"></script>' >< buf ||
      ( '<li><a href="https://twitter.com/Twonky" id="twSoctw"' >< buf && '<li><a href="http://www.facebook.com/Twonky" id="twSocfb"' >< buf ) ) {

    version = "unknown";
    extra   = "";

    url = dir + "/rpc/info_status";
    req = http_get( item:url, port:port );
    buf = http_keepalive_send_recv( port:port, data:req );

    # version|8.2
    # version|7.2.9-6
    # version|7.2.9-13
    ver = eregmatch( pattern:"version\|([0-9.\-]+)", string:buf );
    if( buf =~ "^HTTP/1\.[01] 200" && ver[1] ) {
      version = ver[1];
      concludedUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    } else if( buf =~ "^HTTP/1\.[01] 401" && "Access to this page is restricted" >< buf ) {
      extra = "The Web Console is protected by a password.";
    }

    # CPE is not registered yet
    cpe = build_cpe( value:version, exp:"^([0-9.\-]+)", base:"cpe:/a:twonky:twonky_server:");
    if( isnull( cpe ) )
      cpe = 'cpe:/a:twonky:twonky_server';

    set_kb_item( name:"www/" + port + "/twonky_server", value:version );
    set_kb_item( name:"twonky_server/installed", value:TRUE );

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data: build_detection_report( app:"Twonky Server",
                                               version:version,
                                               install:install,
                                               extra:extra,
                                               cpe:cpe,
                                               concluded:ver[0],
                                               concludedUrl:concludedUrl ),
                                               port:port );
  }
}

exit( 0 );

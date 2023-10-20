# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806024");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-08-19 14:54:43 +0530 (Wed, 19 Aug 2015)");
  script_name("Codoforum Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Product detection");
  script_require_ports("Services/www", 80);
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installed version of Codoforum.

  This script sends an HTTP GET request and tries to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port( default:80 );

if( ! http_can_host_php( port:port ) ) exit(0);

foreach dir( make_list_unique( "/", "/codoforum", "/forum", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache( item: dir + "/index.php", port:port );

  if( ">Welcome to Codoforum<" >< rcvRes && 'content="codoforum' >< rcvRes ) {

    version = "unknown";

    sndReq = http_get(item: dir + "/admin/layout/templates/dashboard.tpl", port:port);
    rcvRes = http_keepalive_send_recv( port:port, data:sndReq );

    ver = eregmatch( pattern:"codoforum.com/news/([0-9.]+)", string:rcvRes );
    if( ver[1] ) version = ver[1];

    tmp_version = version + " under " + install;
    set_kb_item( name:"www/" + port + "/Codoforum", value:tmp_version );
    set_kb_item( name:"Codoforum/Installed", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:codoforum:codoforum:" );
    if( ! cpe )
      cpe= "cpe:/a:codoforum:codoforum:";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Codoforum",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver[0] ),
                                              port:port );
  }
}

exit( 0 );

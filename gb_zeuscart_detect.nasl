# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801250");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-08-10 14:39:31 +0200 (Tue, 10 Aug 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("ZeusCart Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://zeuscart.com/");

  script_tag(name:"summary", value:"The script detects the version of ZeusCart on
  remote host and sets the KB.");

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
if( ! http_can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/Zeuscart", "/zeuscart", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  res = http_get_cache( item:dir + "/index.php", port:port );

  if( egrep( pattern:'target="_blank">ZeusCart</a>', string:res, icase:TRUE ) ) {

    version = "unknown";
    vers = eregmatch( pattern:'<title> ZeusCart V(.[0-9.]+)', string:res );
    if( ! isnull( vers[1] ) ) version = chomp( vers[1] );

    set_kb_item( name:"www/" + port + "/ZeusCart", value:version );
    set_kb_item( name:"zeuscart/installed", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:zeuscart:zeuscart:" );
    if( isnull( cpe ) )
      cpe = "cpe:/a:zeuscart:zeuscart";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"ZeusCart",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:vers[0] ),
                                              port:port );
  }
}

exit( 0 );

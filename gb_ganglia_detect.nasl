# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_tag(name:"cvss_base", value:"0.0");
  script_oid("1.3.6.1.4.1.25623.1.0.103534");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2012-08-13 12:20:02 +0200 (Mon, 13 Aug 2012)");
  script_name("Ganglia Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Ganglia.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

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

foreach dir( make_list_unique("/", "/ganglia","/gang", "/gweb", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  url = dir + "/index.php";
  buf = http_get_cache( item:url, port:port );
  if( ! buf ) continue;

  if( ( "<title>ganglia" >< tolower( buf ) && "Ganglia Web Backend" >< buf) || "There was an error collecting ganglia data" ><buf ) {

    vers = "unknown";

    version = eregmatch( string:buf, pattern:"Ganglia Web Frontend version ([0-9.]+)", icase:TRUE );

    if( ! isnull( version[1] ) ) {
      vers = chomp( version[1] );
    }

    tmp_version = vers + " under " + install;
    set_kb_item( name:"www/" + port + "/ganglia", value:tmp_version );
    set_kb_item( name:"ganglia/installed", value:TRUE );

    cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:ganglia:ganglia-web:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:ganglia:ganglia-web';

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Ganglia",
                                              version:vers,
                                              install:install,
                                              cpe:cpe,
                                              concluded:version[0] ),
                                              port:port );
  }
}

exit( 0 );

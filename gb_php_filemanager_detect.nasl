# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106033");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-07-29 10:33:31 +0700 (Wed, 29 Jul 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("PHP File Manager Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of PHP File Manager.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

port = http_get_port( default:80 );

if( ! http_can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/filemanager", "/fm", http_cgi_dirs( port:port ) ) ) {

  rep_dir = dir;
  if( dir == "/" ) dir = "";

  url = dir + "/index.php";
  res = http_get_cache( item:url, port:port );

  if( "php File Manager - Admin Control Panel" >< res && "gfx/logo_FileManager.gif" >< res ) {

    vers = "unknown";
    set_kb_item( name:"www/" + port + "/phpfilemanager", value:vers );
    set_kb_item( name:"phpfilemanager/installed", value:TRUE );
    set_kb_item( name:"phpfilemanager/detected", value:TRUE );
    set_kb_item( name:"phpfilemanager/http/detected", value:TRUE );

    cpe = "cpe:/a:revived_wire_media:php_file_manager";

    register_product( cpe:cpe, location:rep_dir, port:port, service:"www" );

    log_message( data:build_detection_report( app:"PHP File Manager",
                                              version:vers,
                                              install:rep_dir,
                                              cpe:cpe ),
                                              port:port );
  }
}

exit( 0 );

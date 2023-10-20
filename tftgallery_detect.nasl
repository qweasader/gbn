# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100324");
  script_version("2023-07-28T16:09:08+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:08 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-10-29 12:31:54 +0100 (Thu, 29 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("TFT Gallery Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.tftgallery.org");

  script_tag(name:"summary", value:"This host is running TFT Gallery, an easy-to-use image gallery
  using PHP.");

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
if( ! http_can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/gallery", "/photos", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/index.php";
  buf = http_get_cache( item:url, port:port );
  if( ! buf )
    continue;

  if( egrep( pattern:'<meta name="generator" content="(TFT Gallery|TFTgallery)', string:buf, icase:TRUE ) ) {

    version = "unknown";
    vers = eregmatch( string:buf, pattern: "(TFT Gallery|TFTgallery) ([0-9.]+)", icase:TRUE );

    if( ! isnull( vers[2] ) )
      version = chomp( vers[2] );

    tmp_version = vers + " under " + install;
    set_kb_item( name:"www/" + port + "/tftgallery", value:tmp_version );
    set_kb_item( name:"tftgallery/detected", value:TRUE );

    register_and_report_cpe( app:"TFT Gallery",
                             ver:version,
                             concluded:vers[0],
                             base:"cpe:/a:tftgallery:tftgallery:",
                             expr:"^([0-9.]+)",
                             insloc:install,
                             regPort:port );
    exit( 0 );
  }
}

exit( 0 );

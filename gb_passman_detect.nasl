# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100827");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-09-28 17:11:37 +0200 (Tue, 28 Sep 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Collaborative Passwords Manager (cPassMan) Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://cpassman.org/");

  script_tag(name:"summary", value:"This host is running Collaborative Passwords Manager (cPassMan),
  a Passwords Manager dedicated for managing passwords in a collaborative way.");

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
if( ! http_can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/cpassman", "/cPassMan", "/passman", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";
  url = dir + "/index.php";
  buf = http_get_cache( item:url, port:port );
  if( isnull( buf ) ) continue;

  if( "<title>Collaborative Passwords Manager" >< buf && "cPassMan" >< buf ) {

    vers = "unknown";

    version = eregmatch( string:buf, pattern:"cPassMan(</a>)? ([0-9.]+).*copyright", icase:TRUE );
    if( version[2] ) vers = chomp( version[2] );

    set_kb_item( name:"www/" + port + "/passman", value:vers + " under " + install );
    set_kb_item( name:"cpassman/detected", value:TRUE );

    cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:cpassman:cpassman:" );
    if( isnull( cpe ) )
      cpe = "cpe:/a:cpassman:cpassman";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Collaborative Passwords Manager (cPassMan)",
                                              version:vers,
                                              install:install,
                                              cpe:cpe,
                                              concluded:version[0] ),
                                              port:port );
    exit( 0 );
  }
}

exit( 0 );

# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100186");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-05-06 14:55:27 +0200 (Wed, 06 May 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("Nagios / Nagios Core Detection");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Nagios / Nagios Core.

  The script sends a connection request to the server and attempts to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );

files = make_list( "/main.php", "/main.html" );

foreach dir( make_list_unique( "/nagios", "/monitoring", http_cgi_dirs( port:port ) ) ) {
  install = dir;
  if( dir == "/" ) dir = "";

  foreach file( files ) {
    url = dir + file;
    buf = http_get_cache( item:url, port:port );
    if( isnull( buf ) ) continue;

    if( egrep( pattern: '<TITLE>Nagios( Core)?', string:buf, icase:TRUE ) &&
        ( egrep( pattern:'Nagios( Core)? is licensed under the GNU', string:buf, icase:TRUE ) ||
          "Monitored by Nagios" >< buf ) ||
        'Basic realm="Nagios Access"' >< buf ||
        'Basic realm="Nagios Core"' >< buf ) {

      vers = "unknown";

      version = eregmatch( string:buf, pattern:'Version ([0-9.]+)', icase:TRUE );
      if( ! isnull( version[1] ) ) {
        vers = version[1];
        concluded = version[0];
      } else if( 'Basic realm="Nagios' >< buf ) {
        concluded = 'Basic realm="Nagios';
      }

      set_kb_item( name:"nagios/installed", value:TRUE );

      cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:nagios:nagios:" );
      if( isnull( cpe ) )
        cpe = "cpe:/a:nagios:nagios";

      register_product( cpe:cpe, location:install, port:port, service:"www" );
      log_message( data:build_detection_report( app:"Nagios", version:vers, install:install, cpe:cpe,
                                                concluded:concluded ),
                   port:port );
      exit( 0 );
    }
  }
}

exit( 0 );

# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900611");
  script_version("2023-04-18T10:19:20+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-04-18 10:19:20 +0000 (Tue, 18 Apr 2023)");
  script_tag(name:"creation_date", value:"2009-04-07 09:44:25 +0200 (Tue, 07 Apr 2009)");
  script_name("Squid Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "proxy_use.nasl", "global_settings.nasl");
  script_require_ports("Services/http_proxy", "Services/www", 3128);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of the Squid.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");
include("port_service_func.inc");

port = service_get_port( default:3128, proto:"http_proxy" );

req     = http_get( item:"http://www.$$$$$", port:port );
res     = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
banner  = http_get_remote_headers( port:port );
pattern = "^Server\s*:\s*squid";

if( data = egrep( pattern:pattern, string:res, icase:TRUE ) ) {
  installed = TRUE;
} else {
  if( data = egrep( pattern:pattern, string:banner, icase:TRUE ) ) {
    installed = TRUE;
  }
}

if( installed ) {

  concl = chomp( data );
  vers    = "unknown";
  install = port + "/tcp";
  version = eregmatch( pattern:"^Server\s*:\s*squid/([0-9a-zA-Z.]+)", string:data, icase:TRUE );

  if( version[1] ) {
    vers = version[1];
    set_kb_item( name:"www/" + port + "/Squid", value:vers );
    concl = version[0];
  }

  set_kb_item( name:"squid/detected", value:TRUE );
  set_kb_item( name:"squid/http/detected", value:TRUE );

  cpe = build_cpe( value:vers, exp:"^([0-9.]+.[a-zA-Z0-9]+)", base:"cpe:/a:squid-cache:squid:" );
  if( ! cpe )
    cpe = "cpe:/a:squid-cache:squid";

  register_product( cpe:cpe, location:install, port:port, service:"www" );

  log_message( data:build_detection_report( app:"Squid",
                                            version:vers,
                                            install:install,
                                            cpe:cpe,
                                            concluded:concl ),
               port:port );
}

exit( 0 );

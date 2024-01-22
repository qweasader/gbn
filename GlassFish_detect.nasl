# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100190");
  script_version("2023-12-19T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-12-19 05:05:25 +0000 (Tue, 19 Dec 2023)");
  script_tag(name:"creation_date", value:"2009-05-10 17:01:14 +0200 (Sun, 10 May 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Oracle / Eclipse GlassFish Server Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Oracle / Eclipse GlassFish Server.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:8080 );

buf = http_get_cache( item:"/index.html", port:port );
buf2 = http_get_cache( item:"/vt-test-non-existent.html", port:port, fetch404:TRUE );

if( ( "<title>GlassFish Server" ><buf && "Server Running</title>" >< buf ) ||
      egrep( pattern: 'Server:.*GlassFish.*', string: buf, icase: TRUE ) ||
      ( "<title>GlassFish Server" >< buf2 && "Error report</title>" >< buf2  ) ||
        "Log In to GlassFish Administration Console" >< buf ) {

  # nb: For JavaServer Faces active checks (See "login.jsf" below)
  set_kb_item( name:"www/javaserver_faces/detected", value:TRUE );
  set_kb_item( name:"www/javaserver_faces/" + port + "/detected", value:TRUE );

  vers = "unknown";
  install = "/";

  #Banner:
  #X-Powered-By: Servlet/3.0 JSP/2.2 (GlassFish Server Open Source Edition 3.1.2.2 Java/Oracle Corporation/1.7)
  #Server: GlassFish Server Open Source Edition 3.1.2.2
  #Server: GlassFish Server Open Source Edition  4.1
  #X-Powered-By: Servlet/3.1 JSP/2.3 (GlassFish Server Open Source Edition  4.1  Java/Oracle Corporation/1.7)

  version = eregmatch( string:buf, pattern:'Server:.*GlassFish[^0-9]+v([0-9.]+)', icase:TRUE );
  if( isnull( version[1] ) ) {
    version = eregmatch( string:buf, pattern:"GlassFish Server( Open Source Edition)?( )? ([0-9.]+)", icase:TRUE );
    if( ! isnull( version[3] ) ) {
      vers = version[3];
    } else {
      version = eregmatch( string:buf2, pattern:"GlassFish Server( Open Source Edition)?( )? ([0-9.]+)", icase:TRUE );
      if( ! isnull( version[3] ) ) vers = version[3];
    }
  } else {
    vers = version[1];
  }

  if( egrep( pattern:"Location:.*login.jsf", string:buf ) ||
    ( egrep( pattern:"Log In to.*GlassFish", string:buf ) && "<title>Login" >< buf ) ) {

    report = "The GlassFish Administration Console is running at this port.";
    set_kb_item( name:"www/" + port + "/GlassFishAdminConsole", value:TRUE );
    set_kb_item( name:"GlassFishAdminConsole/port", value:port );
  }

  cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:oracle:glassfish_server:" );
  if( ! cpe )
    cpe = "cpe:/a:oracle:glassfish_server";

  register_product( cpe:cpe, location:install, port:port, service:"www" );

  set_kb_item( name:"GlassFish/installed", value:TRUE );
  set_kb_item( name:"glassfish/detected", value:TRUE );
  set_kb_item( name:"glassfish/http/detected", value:TRUE );
  set_kb_item( name:"glassfish_or_sun_java_appserver/installed", value:TRUE );

  log_message( data:build_detection_report( app:"Oracle / Eclipse GlassFish Server", version:vers, install:install, cpe:cpe, concluded:version[0], extra:report ),
               port:port );
}

exit( 0 );

# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140066");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-11-17 10:30:27 +0100 (Thu, 17 Nov 2016)");
  script_name("Keycloak Detection");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts
  to detect Keycloak and also to extract its version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:80 );

url = '/auth/';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "<title>Welcome to Keycloak</title>" >!< buf || ">Administration Console<" >!< buf ) exit( 0 );

set_kb_item( name:"keycloak/detected", value:TRUE );
cpe = 'cpe:/a:redhat:keycloak';

url = '/auth/admin/master/console/';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

# <script src="http://localhost:8080/auth/resources/2.3.0.final/admin/keycloak/lib/angular/angular.js"></script>
v = eregmatch( pattern:'/auth/resources/([0-9.]+)\\.([a-z]+[^/]+)/admin/', string:buf );

if( ! isnull( v[1] ) )
{
  version = v[1];
  cpe += ':' + version;
  rep_version = version;
}

if( ! isnull( v[2] ) )
{
  set_kb_item( name:'keycloak/release_type', value:v[2] );
  rep_version += ' (' + v[2] + ')';
}

register_product( cpe:cpe, location:"/", port:port, service:"www" );

report = build_detection_report( app:"Keycloak", version:rep_version, install:"/", cpe:cpe, concluded:v[0] );

log_message( port:port, data:report );
exit( 0 );


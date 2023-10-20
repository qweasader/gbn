# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105307");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-06-24 15:27:54 +0200 (Wed, 24 Jun 2015)");
  script_name("F5 LineRate Web Configuration Detection");

  script_tag(name:"summary", value:"The script sends a connection request to the server and
 attempts to detect F5 LineRate from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:8443 );

url = "/login";;
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "<title>LineRate Login</title>" >< buf && "X-Powered-By: Express" >< buf )
{
  cpe = 'cpe:/a:f5:linerate';
  install = "/";

  register_product( cpe:cpe, location:install, port:port, service:"www" );

  log_message( data: build_detection_report( app:"F5 LineRate Configuration Utility",
                                             version:'unknown',
                                             install:install,
                                             cpe:cpe,
                                             concluded: 'HTTP-Request' ),
               port:port );
}
exit(0);


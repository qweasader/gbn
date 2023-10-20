# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113304");
  script_version("2023-07-20T05:05:18+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:18 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-11-15 10:40:22 +0100 (Thu, 15 Nov 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_name("Netis Router No Authentication Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_netis_router_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("netis/router/detected");

  script_tag(name:"summary", value:"Netis Routers do not require authentication by default.");
  script_tag(name:"impact", value:"Without a password, any remote attacker can access the device
  with administrative privileges.");
  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"solution", value:"In the 'Advanced' Settings, go to
  'System Tools' -> 'Password' and set a username and a secure password.");

  script_xref(name:"URL", value:"http://www.netis-systems.com/Home/info/id/2.html");
  script_xref(name:"URL", value:"http://www.netis-systems.com/Business/info/id/2.html");

  exit(0);
}

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );

if( ! model = get_kb_item( "netis/router/model" ) ) exit( 0 );
CPE = "cpe:/h:netis:" + model;

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! location = get_app_location( cpe: CPE, port: port ) ) exit( 0 );

if( location == "/" ) {
  location = "";
}

url_one = location + "/script/netcore.js";
url_two = location + "/config/config.js";

buf_one = http_get_cache( port: port, item: url_one );
buf_two = http_get_cache( port: port, item: url_two );

if( buf_one =~ '200 OK' && buf_one =~ 'var netcore' && buf_one !~ 'Basic realm' && buf_one !~ 'WWW-Authenticate' &&
    buf_two =~ '200 OK' && buf_two =~ 'name[ ]*:[ ]*"management"' ) {
  report = "It was possible to access the admin interface without login credentials.";
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

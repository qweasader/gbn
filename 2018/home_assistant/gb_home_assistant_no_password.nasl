# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:home-assistant:home-assistant";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113250");
  script_version("2023-06-22T10:34:15+0000");
  script_tag(name:"last_modification", value:"2023-06-22 10:34:15 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"creation_date", value:"2018-08-22 12:10:24 +0200 (Wed, 22 Aug 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Home Assistant Dashboard No Password");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_home_assistant_consolidation.nasl");
  script_require_ports("Services/www", 8123);
  script_mandatory_keys("home_assistant/http/detected");

  script_tag(name:"summary", value:"By default, the full control dashboard of Home Assistant
  does not require a password.");

  script_tag(name:"vuldetect", value:"Tries to access control dashboard without a password.");

  script_tag(name:"affected", value:"All versions of Home Assistant.");

  script_tag(name:"solution", value:"Set a password.");

  exit(0);
}

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );

if( ! port = get_app_port( cpe: CPE, service: "www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe: CPE, port: port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

path = dir + "/states";
buf = http_get_cache( port: port, item: path );
buf = ereg_replace( pattern: '[\r\n]*', string:buf, replace:'', icase: TRUE );
if( buf =~ "^HTTP/1\.[01] 200" && buf =~ 'window.noAuth[ ]*=[ ]*["\']?(true|1)["\']?' ) {
  report = "It was possible to access the control dashboard without a password.";
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

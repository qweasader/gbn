# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112183");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2018-01-11 12:07:00 +0100 (Thu, 11 Jan 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Sangoma NetBorder/Vega Session Controller Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.sangoma.com/products/sbc/");

  script_tag(name:"summary", value:"This script sends an HTTP GET request to figure out whether a
  web-based service of Sangoma Session Border Controller (SBC) is running on the target host, and,
  if so, which version is installed.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

hw_cpe = "cpe:/h:sangoma:netborder%2fvega_session";
hw_name = "Sangoma NetBorder/Vega Session Controller";
os_cpe = "cpe:/o:sangoma:netborder%2fvega_session_firmware";
os_name = hw_name + " Firmware";

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  installed = FALSE;
  install = dir;
  if( dir == "/" ) dir = "";

  foreach file( make_list( "/", "/index.php" ) ) {

    url = dir + file;
    res = http_get_cache( item:url, port:port );

    if( "Session Controller" >< res && 'SNG_logo.png" alt="Sangoma"' >< res ) {
      installed = TRUE;
      break;
    }
  }

  if( installed ) {

    set_kb_item( name:"sangoma/nsc/detected", value:TRUE );
    version = "unknown";

    os_register_and_report( os:os_name, cpe:os_cpe, desc:"Sangoma NetBorder/Vega Session Controller Detection", runs_key:"unixoide" );

    register_product( cpe:os_cpe, location:install, port:port, service:"www" );
    register_product( cpe:hw_cpe, location:install, port:port, service:"www" );

    report  = build_detection_report( app:os_name, version:version, install:install, cpe:os_cpe );
    report += '\n\n';
    report += build_detection_report( app:hw_name, install:install, cpe:hw_cpe, skip_version:TRUE );

    log_message( port:port, data:report );
  }
}

exit( 0 );

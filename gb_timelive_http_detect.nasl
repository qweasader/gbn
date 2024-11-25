# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902480");
  script_version("2024-06-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2011-09-30 15:58:03 +0200 (Fri, 30 Sep 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("TimeLive Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl",
                      "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of TimeLive.");

  script_xref(name:"URL", value:"https://www.livetecs.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

if( ! http_can_host_asp( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/", "/timelive", "/timetracking", "/TimeLive", "/TimeTracking", http_cgi_dirs( port:port ) ) ) {
  install = dir;
  if( dir == "/" )
    dir = "";

  res = http_get_cache( item:dir + "/default.aspx", port:port );

  if( res =~ "^HTTP/1\.[01] 200" && "Livetecs LLC" >< res &&
      "TimeLive - Online web timesheet and time tracking solution" >< res ) {
    version = "unknown";

    ver = eregmatch( pattern:">v ([0-9.]+)", string:res );
    if( isnull( ver[1] ) )
      # >Version 8.2.1<
      ver = eregmatch( pattern:">Version ([0-9.]+)<", string:res );

    if( ! isnull( ver[1] ) )
      version = ver[1];

    set_kb_item( name:"timelive/detected", value:TRUE );
    set_kb_item( name:"timelive/http/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:livetecs:timeline:" );
    if( ! cpe )
      cpe = "cpe:/a:livetecs:timeline";

    os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", port:port,
                            desc:"TimeLive Detection (HTTP)", runs_key:"windows" );

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"TimeLive", version:version, install:install, cpe:cpe,
                                              concluded:ver[0] ),
                 port:port );
    exit( 0 );
  }
}

exit( 0 );

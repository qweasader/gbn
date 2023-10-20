# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113239");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-08-01 11:40:00 +0200 (Wed, 01 Aug 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Web Remote Viewer Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects if a target is running the Web Remote Viewer software.");

  script_xref(name:"URL", value:"https://www.cctvcamerapros.com/Remote-Internet-DVR-Viewer-s/87.htm");

  exit(0);
}

CPE = "cpe:/a:dvr:web_remote_viewer:";

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");

port = http_get_port( default: 80 );

foreach url ( make_list_unique( "/", http_cgi_dirs( port: port ) ) ) {
  buf = http_get_cache( port: port, item: "/" );
  if( buf !~ '[Ww]{3}-[Aa]uthenticate:[ ]?[Bb]asic [Rr]ealm[ ]?=[ ]?"[Ww][Ee][Bb][ ]?[Rr]emote[ ]?[Vv]iewer"' )
    continue;

  set_kb_item( name: "web_remote_viewer/detected", value: TRUE );
  set_kb_item( name: "web_remote_viewer/http/port", value: port );

  version = "unknown";

  register_and_report_cpe( app: "Web Remote Viewer",
                           ver: version,
                           base: CPE,
                           expr: '([0-9.]+)',
                           insloc: url,
                           regPort: port,
                           conclUrl: url);

  break;
}

exit( 0 );

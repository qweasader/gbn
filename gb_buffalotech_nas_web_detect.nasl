# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112353");
  script_version("2023-04-18T10:19:20+0000");
  script_tag(name:"last_modification", value:"2023-04-18 10:19:20 +0000 (Tue, 18 Apr 2023)");
  script_tag(name:"creation_date", value:"2018-08-08 13:38:12 +0200 (Wed, 08 Aug 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Buffalotech NAS Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 9000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Buffalo LinkStation / TeraStation Network Attached Storage devices.

  The script sends a connection request to the server and attempts to
  determine if the remote host is a LinkStation / TeraStation device from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc" );
include("host_details.inc");

CPE = "cpe:/h:buffalotech:nas:";
fingerprint = "b810a5f2a0528eafd7d23e25380aa03d";

port = http_get_port( default:9000 );

foreach dir( make_list( "/", "/ui" ) ) {

  if( dir == "/" )
    dir = "";

  url = dir + "/";
  res = http_get_cache( item:url, port:port );

  logo_req = http_get( port:port, item:dir + "/images/logo.png" );
  logo_res = http_keepalive_send_recv( port:port, data:logo_req, bodyonly:TRUE );

  if( ! isnull( logo_res ) )
    md5 = hexstr( MD5( logo_res ) );

  if( "<title>WebAccess</title>" >< res && 'xtheme-buffalo.css">' >< res && fingerprint == md5 ) {
    found = TRUE;
    break;
  }
}

if( ! found ) {
  url = "/cgi-bin/top.cgi";
  res = http_get_cache( item:url, port:port );
  if( res && res =~ "^HTTP/1\.[01] 200" && ( 'value="View LinkStation manual"' >< res || "<title>LinkStation" >< res ||
                                             'value="View TeraStation manual"' >< res || "<title>TeraStation" >< res ) )
    found = TRUE;
}

if( found ) {

  set_kb_item( name:"buffalo/linkstation_or_terastation/detected", value:TRUE );
  set_kb_item( name:"buffalo/nas/detected", value:TRUE );
  set_kb_item( name:"buffalo/nas/http/port", value:port );

  version = "unknown";

  register_and_report_cpe( app:"Buffalo LinkStation / TeraStation",
                           ver:version,
                           base:CPE,
                           expr:"([0-9.]+)",
                           insloc:"/",
                           regPort:port,
                           conclUrl:url );
}

exit(0);

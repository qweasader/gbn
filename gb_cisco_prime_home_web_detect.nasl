# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140147");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-02-02 15:33:27 +0100 (Thu, 02 Feb 2017)");
  script_name("Cisco Prime Home Detection");

  script_tag(name:"summary", value:"This script performs HTTP based detection of Cisco Prime Home");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone AG");
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

urls = make_list( "/", "/prime-home/login/", "/web/guest" );

foreach url ( urls )
{
  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( ( "<title>Cisco Prime Home Login</title>" >!< buf && ( 'productFamily">Cisco Prime<' >!< buf || 'productName">Home<' >!< buf ) &&
      ( 'powered-by"> Cisco Prime Home' >!< buf && "buildVersionInfoHtml" >!< buf ) ) ) continue;

  cpe = 'cpe:/a:cisco:prime_home';

  set_kb_item( name:"cisco/prime_home/installed", value:TRUE );

  version = 'unknown';

  # 5.2.0.0.1-rc.3
  # 5.1.2.2
  # 5.1.2.3
  # 6.4.0.1
  # 6.5.1.0
  if( "acsVersion" >< buf )
    v = eregmatch( pattern:'<div class="acsVersion">([0-9.]+[^<]+)</div>', string:buf );
  else
    v = eregmatch( pattern:'buildVersionInfoHtml\\(this\\)">([0-9.]+[^<]+)</a>', string:buf );

  if( ! isnull( v[1] ) )
  {
    version = v[1];
    cpe += ':' + version;
    set_kb_item( name:"cisco/prime_home/version", value:version );
  }

  register_product( cpe:cpe, location:"'prime-home/", port:port, service:"www" );

  report = build_detection_report( app:"Cisco Prime Home", version:version, install:url, cpe:cpe, concluded:v[0], concludedUrl:url );

  log_message( port:port, data:report );

  exit( 0 );
}

exit( 0 );


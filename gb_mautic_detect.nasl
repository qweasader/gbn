# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108182");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2017-06-13 12:57:33 +0200 (Tue, 13 Jun 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Mautic Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.mautic.org/");

  script_tag(name:"summary", value:"Detection of installed version
  of Mautic.

  This script sends an HTTP GET request and tries to ensure the presence of
  Mautic from the response.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", "/mautic", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  url = dir + "/index.php/s/login";
  res = http_get_cache( item:url, port:port );

  if( res =~ "^HTTP/1\.[01] 200" && ( "<title>Mautic</title>" >< res || "Mautic. All Rights Reserved." >< res || "var mauticBasePath" >< res || "var mauticBaseUrl" >< res ) ) {

    version = "unknown";
    conclUrl = NULL;

    # This is protected by a .htaccess but still try to gather the version if unprotected
    url = dir + "/app/version.txt";
    req = http_get( item:url, port:port );
    res = http_keepalive_send_recv( data:req, port:port, bodyonly:FALSE );

    vers = egrep( pattern:"^([0-9.]+)$", string:res );

    if( res =~ "^HTTP/1\.[01] 200" && vers ) {
      version = chomp( vers );
      conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    }

    set_kb_item( name:"Mautic/installed", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:mautic:mautic:" );
    if( ! cpe )
      cpe = "cpe:/a:mautic:mautic";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Mautic",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concludedUrl:conclUrl,
                                              concluded:version ),
                                              port:port );
  }
}

exit( 0 );

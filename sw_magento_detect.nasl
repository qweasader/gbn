# SPDX-FileCopyrightText: 2015 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105227");
  script_version("2024-01-09T05:06:46+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-01-09 05:06:46 +0000 (Tue, 09 Jan 2024)");
  script_tag(name:"creation_date", value:"2015-02-09 12:00:00 +0100 (Mon, 09 Feb 2015)");
  script_name("Magento Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Magento.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");
include("version_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) )
  exit( 0 );

rootInstalled = FALSE;

foreach dir( make_list_unique( "/", "/magento", "/shop", http_cgi_dirs( port:port ) ) ) {

  if( rootInstalled )
    break;

  install = dir;
  if( dir == "/" )
    dir = "";

  flag = FALSE;
  outdatedChangelog = FALSE;
  CE = FALSE;
  EE = FALSE;

  url1 = dir + "/admin/";
  res1 = http_get_cache( item:url1, port:port );

  url2 = dir + "/";
  res2 = http_get_cache( item:url2, port:port );

  url3 = dir + "/RELEASE_NOTES.txt";
  res3 = http_get_cache( item:url3, port:port );

  url4 = dir + "/downloader/";
  res4 = http_get_cache( item:url4, port:port );

  if( res1 && "Magento Inc." >< res1 || res2 && ( "/skin/frontend/" >< res2 || "text/x-magento-init" >< res2 ) ||
      res3 && "=== Improvements ===" >< res3 || res4 && "Magento Connect Manager ver." >< res4 ) {

    version = "unknown";
    if( dir == "" )
      rootInstalled = TRUE;

    ver = eregmatch( pattern:"==== ([0-9\.]+) ====", string:res3 );

    # nb: The RELEASE_NOTES.txt is not updated between version 1.7.0.2 and 1.9.1.0
    if( ver[1] && ( version_is_less_equal( version:ver[1], test_version:"1.7.0.2" ) &&
        "NOTE: Current Release Notes are maintained at:" >!< res3 ) ||
        version_is_greater_equal( version:ver[1], test_version:"1.9.1.0" ) ) {
      conclUrl = http_report_vuln_url( port:port, url:url3, url_only:TRUE );
      version  = ver[1];
      flag     = TRUE;
      if( "NOTE: Current Release Notes are maintained at:" >< res3 )
        outdatedChangelog = TRUE;
    }

    if( ! flag ) {
      ver = eregmatch( pattern:"Magento Connect Manager ver. ([0-9\.]+)", string:res4 );
      if( ver[1] && version_is_less_equal( version:ver[1], test_version:"1.7.0.2" ) && ! outdatedChangelog ) {
        conclUrl = http_report_vuln_url( port:port, url:url4, url_only:TRUE );
        version  = ver[1];
      }
    }

    # nb: First try to read from Release Notes
    if( res3 && "magento" >< res3 && "=== Improvements ===" >< res3 ) {
      if( res3 =~ "(c|C)ommunity_(e|E)dition" ) {
        CE    = TRUE;
        extra = '\nEdition gathered from:\n' + http_report_vuln_url( port:port, url:url3, url_only:TRUE );
      }
      else if( res3 =~ "(e|E)nterprise (E|e)dition" ) {
        EE    = TRUE;
        extra = '\nEdition gathered from:\n' + http_report_vuln_url( port:port, url:url3, url_only:TRUE );
      }
    }

    # From version 2 on the Major/Minor version and edition can get retrieved over /magento_version.
    # However, this doesn't include any patch information
    # Magento/2.2 (Enterprise)
    # Magento/2.3 (Community)
    url7 = dir + "/magento_version";
    res7 = http_get_cache( item:url7, port:port );
    ver = eregmatch( pattern:"Magento/([0-9.]+) \((Community|Enterprise)\)", string:res7 );
    if( ! isnull( ver[1] ) ) {
      version = ver[1];
      conclUrl = http_report_vuln_url( port:port, url:url7, url_only:TRUE );
      if( ! isnull( ver[2] ) ) {
        if( ver[2] == "Enterprise" )
          EE = TRUE;
        else
          CE = TRUE;
      }
    }

    # nb: License opens up on accessing URL: /css/styles.css
    if( ! EE || ! CE ) {
      # nb: URL for Enterprise Edition
      url5 = dir + "/errors/enterprise/css/styles.css";
      res5 = http_get_cache( item:url5, port:port );

      if( res5 && res5 =~ "(M|m)agento (E|e)nterprise (E|e)dition" && res5 =~ "license.*enterprise.edition" ) {
        EE    = TRUE;
        extra = '\nEdition gathered from:\n' + http_report_vuln_url( port:port, url:url5, url_only:TRUE );
      } else {
        # nb: URL for Community Edition
        url6 = dir + "/errors/default/css/styles.css";
        res6 = http_get_cache( item:url6, port:port );

        if( res6 && res6 =~ "(M|m)agento" && res6 =~ "license.*opensource.*Free" ) {
          CE    = TRUE;
          extra = '\nEdition gathered from:\n' + http_report_vuln_url( port:port, url:url6, url_only:TRUE );
        }
      }
    }

    if( CE ) {
      set_kb_item( name:"magento/edition/" + port + "/" + install, value:"CE" );
      app = "Magento (Community Edition)";
    } else if( EE ) {
      set_kb_item( name:"magento/edition/" + port + "/" + install, value:"EE" );
      app = "Magento (Enterprise Edition)";
    } else {
      app = "Magento (Unknown Edition)";
    }

    set_kb_item( name:"magento/installed", value:TRUE );
    set_kb_item( name:"magento/detected", value:TRUE );
    set_kb_item( name:"magento/http/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:"([0-9a-z.]+)", base:"cpe:/a:magentocommerce:magento:" );
    if( ! cpe )
      cpe = "cpe:/a:magentocommerce:magento";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:app,
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              extra:extra,
                                              concludedUrl:conclUrl,
                                              concluded:ver[0] ),
                 port:port );
  }
}

exit( 0 );

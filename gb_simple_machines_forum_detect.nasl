# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800557");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-04-23 08:16:04 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Simple Machines Forum (SMF) Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.simplemachines.org/");

  script_tag(name:"summary", value:"This script detects the installed version of Simple Machines Forum (SMF).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");
include("version_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) ) exit( 0 );

rootInstalled = FALSE;
versionDebug  = FALSE;

foreach dir( make_list_unique( "/", "/community", "/smf", "/smf1", "/smf2", "/forum", "/board", "/sm_forum", http_cgi_dirs( port:port ) ) ) {

  if( rootInstalled ) break;
  found = FALSE;

  install = dir;
  if( dir == "/" ) dir = "";

  res = http_get_cache( item:dir + "/index.php", port:port );
  if( res =~ "^HTTP/1\.[01] 200" && ( "Powered by SMF" >< res || ">Simple Machines<" >< res ) ) {
    found = TRUE;
  } else {
    res = http_get_cache( item:dir + "/", port:port );
    if( res =~ "^HTTP/1\.[01] 200" && ( "Powered by SMF" >< res || ">Simple Machines<" >< res ) ) {
      found = TRUE;
    }
  }

  if( found ) {

    final_ver = "unknown";
    if( dir == "" ) rootInstalled = TRUE;

    vers = eregmatch( pattern:">SMF ([0-9.]+)\.?(RC[0-9])?</a>", string:res );
    if( ! isnull( vers[1] ) ) {
      concluded = vers[0];
      if( isnull( vers[2] ) ) {
        final_ver = vers[1];
      } else {
        final_ver = vers[1] + "." + vers[2];
      }
    }

    if( final_ver == "unknown" ) {
      vers = eregmatch( pattern:">Powered by SMF ([0-9.]+)\.?(RC[0-9])?</a>", string:res );
      if( ! isnull( vers[1] ) ) {
        if( isnull( vers[2] ) ) {
          final_ver = vers[1];
        } else {
          final_ver = vers[1] + "." + vers[2];
        }
      }
    }

    if( final_ver == "unknown" ) {

      highest_ver = "unknown";

      # If version is hidden try some common backup file names to
      # find the highest available version exposed.
      foreach file( make_list( "/index.php~", "/proxy.php~", "/Sources/Admin.php", "/Sources/Class-CurlFetchWeb.php~",
                               "/Sources/LogInOut.php~", "/Sources/ManageServer.php~", "/Sources/Post.php~",
                               "/Sources/Profile-Modify.php~", "/Sources/Profile-View.php~", "/Sources/SendTopic.php~",
                               "/Sources/Subs.php~", "/Sources/Subs-Db-mysql.php~", "/Sources/Who.php~",
                               "/Themes/core/Login.template.php~", "/Themes/core/index.template.php~",
                               "/Themes/default/Login.template.php~", "/Themes/default/index.template.php~" ) ) {
        url = dir + file;
        req = http_get( item:url, port:port );
        res = http_keepalive_send_recv( port:port, data:req );

        vers = eregmatch( pattern:"\* @version ([0-9.]+)\.?(RC[0-9])?", string:res );
        if( ! isnull( vers[1] ) ) {
          if( highest_ver == "unknown" ) {
            if( isnull( vers[2] ) ) {
              highest_ver = vers[1];
            } else {
              highest_ver = vers[1] + "." + vers[2];
            }
            concluded = vers[0];
            conclUrl  = http_report_vuln_url( port:port, url:url, url_only:TRUE );
          }
          if( isnull( vers[2] ) ) {
            tmp_ver = vers[1];
          } else {
            tmp_ver = vers[1] + "." + vers[2];
          }
          if( versionDebug ) display( "Current detected version in " + url + ": " + tmp_ver + ", previous version: " + highest_ver + '\n' );
          if( version_is_greater( version:tmp_ver, test_version:highest_ver ) ) {
            highest_ver = tmp_ver;
            concluded   = vers[0];
            conclUrl    = http_report_vuln_url( port:port, url:url, url_only:TRUE );
          }
        }
      }
      if( concluded ) vers[0] = concluded;
      if( highest_ver != "unknown" ) final_ver = highest_ver;
    }

    set_kb_item( name:"www/can_host_tapatalk", value:TRUE ); # nb: Used in sw_tapatalk_detect.nasl for plugin scheduling optimization
    set_kb_item( name:"SMF/installed",value:TRUE );
    set_kb_item( name:"www/" + port + "/SMF", value:final_ver + " under " + install );

    cpe = build_cpe( value:final_ver, exp:"^([0-9.]+)(RC[0-9])?", base:"cpe:/a:simplemachines:smf:" );
    if( isnull( cpe ) )
      cpe = "cpe:/a:simplemachines:smf";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Simple Machines Forum (SMF)",
                                              version:final_ver,
                                              install:install,
                                              cpe:cpe,
                                              concludedUrl:conclUrl,
                                              concluded:vers[0] ),
                                              port:port );
  }
}

exit( 0 );

# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809413");
  script_version("2023-05-15T09:08:55+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-05-15 09:08:55 +0000 (Mon, 15 May 2023)");
  script_tag(name:"creation_date", value:"2016-09-27 12:37:02 +0530 (Tue, 27 Sep 2016)");
  script_name("Nextcloud Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installed version of Nextcloud.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

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
include("misc_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) )
  exit( 0 );

host = http_host_name( dont_add_port:TRUE );

foreach dir( make_list_unique( "/", "/nc", "/nextcloud", "/Nextcloud", "/cloud", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/status.php";
  buf = http_get_cache( item:url, port:port );

  # nb: Try again with the IP which might be included in the trusted_domain setting.
  # This could could allow us to gather the version.
  if( "You are accessing the server from an untrusted domain" >< buf ) {
    req = http_get_req( port:port, url:url, host_header_use_ip:TRUE );
    buf = http_keepalive_send_recv( port:port, data:req );
  }

  # nb: Don't check for 200 as a 400 will be returned when accessing via an untrusted domain
  # Example responses:
  # {"installed":true,"maintenance":false,"needsDbUpgrade":false,"version":"12.0.0.29","versionstring":"12.0.0","edition":"","productname":"Nextcloud"}
  # {"installed":true,"maintenance":false,"needsDbUpgrade":false,"version":"12.0.1.3","versionstring":"12.0.1 RC4","edition":"","productname":"Nextcloud"}
  # {"installed":true,"maintenance":false,"needsDbUpgrade":false,"version":"18.0.6.0","versionstring":"18.0.6","edition":"","productname":"Nextcloud","extendedSupport":false}
  if( "egroupware" >!< tolower( buf ) && # EGroupware is using the very same status.php
      buf !~ '"productname":"[^"]*ownCloud[^"]*"' && # Don't detect ownCloud as Nextcloud
    ( egrep( string:buf, pattern:'"installed":("true"|true),("maintenance":("true"|true|"false"|false),)?("needsDbUpgrade":("true"|true|"false"|false),)?"version":"([0-9.]+)","versionstring":"([0-9. a-zA-Z]+)","edition":"(.*)"' ) ||
      ( "You are accessing the server from an untrusted domain" >< buf && ">Nextcloud<" >< buf ) ||
      buf =~ '"productname":"[^"]*Nextcloud[^"]*"' ) ) { # Last fallback if the syntax of the status has changed or the product is themed.

    version = "unknown";
    extra = NULL;
    isNC = FALSE;
    conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

    #Basic auth check for default_http_auth_credentials.nasl
    foreach authurl( make_list( dir + "/remote.php/dav", dir + "/remote.php/webdav" ) ) {

      req = http_get( item:authurl, port:port );
      buf2 = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

      if( buf2 =~ "^HTTP/1\.[01] 401" ) {
        set_kb_item( name:"www/content/auth_required", value:TRUE );
        set_kb_item( name:"www/" + host + "/" + port + "/content/auth_required", value:authurl );
        break;
      }
    }

    ver = eregmatch( string:buf, pattern:'version":"([0-9.]+)","versionstring":"([0-9. a-zA-Z]+)"', icase:TRUE );
    if( ! isnull( ver[2] ) )
      version = ereg_replace( pattern:" ", replace:"", string:ver[2] );

    ## Version fingerprinting, as we can't differ between ownCloud and Nextcloud before Nextcloud11
    # 9.0.50 was the first release of Nextcloud.
    if( version_in_range( version:version, test_version:"9.0.50", test_version2:"9.0.99" ) )
      isNC = TRUE;

    # Nextcloud10 has e.g. "version":"9.1.2.2","versionstring":"10.0.2"
    if( ver[1] =~ "9.1.([0-9]+)" && ver[2] =~ "10.0.([0-9]+)" )
      isNC = TRUE;

    # Valid for Nextcloud11+
    # nb: Using a regex here because the productname could also contain something like "MyCompany Nextcloud".
    if( buf =~ '"productname":"[^"]*Nextcloud[^"]*"' )
      isNC = TRUE;

    # This was also added in a later Nextcloud version and doesn't exist in ownCloud (at least up to 10.5).
    if( buf =~ ',"extendedSupport":(false|true)' )
      isNC = TRUE;

    if( "You are accessing the server from an untrusted domain" >< buf && ">Nextcloud<" ) {
      extra = "Nextcloud is blocking full access to this server because the scanner is accessing the server via an untrusted domain.";
      extra += " To fix this configure the scanner to access the server on the expected domain.";
      isNC = TRUE;
    }

    if( ! isNC )
      continue;

    set_kb_item( name:"nextcloud/install/" + host + "/" + port + "/" + install, value:TRUE ); # For gb_owncloud_detect.nasl to avoid double detection of Nextcloud and ownCloud
    set_kb_item( name:"owncloud_or_nextcloud/installed", value:TRUE );
    set_kb_item( name:"nextcloud/installed", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.a-zA-Z]+)", base:"cpe:/a:nextcloud:nextcloud_server:" );
    if( ! cpe )
      cpe = "cpe:/a:nextcloud:nextcloud_server";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Nextcloud",
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

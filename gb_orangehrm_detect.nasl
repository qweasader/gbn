# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100850");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-10-12 12:50:34 +0200 (Tue, 12 Oct 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("OrangeHRM Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.orangehrm.com/");

  script_tag(name:"summary", value:"This host is running OrangeHRM, a Human Resource management and
  development system.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");
include("cpe.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/", "/orangehrm", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  # nb: Newer versions use a very specific pattern
  foreach page( make_list_unique( "/login.php", "/", "/symfony/web/index.php/auth/login" ) ) {

    url = dir + page;
    buf = http_get_cache( item:url, port:port );
    if( ! buf || buf !~ "^HTTP/1\.[01] 200" )
      continue;

    # Newer versions:
    # <title>OrangeHRM</title>
    # <div id="footer" >
    #     <div>
    #     OrangeHRM 4.3.1<br/>
    #     &copy; 2005 - 2019 <a href="http://www.orangehrm.com" target="_blank">OrangeHRM, Inc</a>. All rights reserved.
    #    </div>
    # but without the "Login Name:"
    #
    if( ( "<title>OrangeHRM" >< buf && "&copy; OrangeHRM Inc." >< buf && "Login Name :" >< buf ) ||
        ( buf =~ '<title>[^<]*OrangeHRM' && ( ">OrangeHRM, Inc<" >< buf || "//www.orangehrm.com" >< buf || "js/orangehrm.validate.js" >< buf || "OrangeHRM on " >< buf ) ) ) {

      vers = "unknown";

      version = eregmatch( string:buf, pattern:"OrangeHRM</a> ver ([0-9.]+)", icase:TRUE );
      if( version[1] )
        vers = chomp( version[1] );

      if( vers == "unknown" ) {
        # OrangeHRM 4.3.1<br/>
        # but have seen something like the following as well:
        # SS HRM 3.3.1<br/>
        # which was actually also an OrangeHM and which also had the "OrangeHRM" title.
        # Not sure if this is caused by some theming...
        version = eregmatch( string:buf, pattern:"(Orange| )HRM ([0-9.]+)<", icase:TRUE );
        if( version[2] )
          vers = version[2];
      }

      set_kb_item( name:"www/" + port + "/orangehrm", value:vers + " under " + install );
      set_kb_item( name:"orangehrm/detected", value:TRUE );

      cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:orangehrm:orangehrm:" );
      if( ! cpe )
        cpe = "cpe:/a:orangehrm:orangehrm";

      register_product( cpe:cpe, location:install, port:port, service:"www" );

      log_message( data:build_detection_report( app:"OrangeHRM",
                                                version:vers,
                                                install:install,
                                                cpe:cpe,
                                                concluded:version[0] ),
                                                port:port );
      exit( 0 );
    }
  }
}

exit( 0 );

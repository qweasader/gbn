# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{

  script_oid("1.3.6.1.4.1.25623.1.0.103742");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_tag(name:"qod_type", value:"remote_banner");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2013-06-20 11:43:29 +0200 (Thu, 20 Jun 2013)");
  script_name("GLPI Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of GLPI.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");
  exit(0);
}

CPE = "cpe:/a:glpi-project:glpi:";

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port( default: 80 );
if( ! http_can_host_php( port: port ) ) exit( 0 );
version = "unknown";

foreach dir( make_list_unique( "/glpi", http_cgi_dirs( port: port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";
  url = dir + "/";
  buf = http_get_cache( item: url, port: port );
  #nb: Some instances return an empty response for "/", but yield the content on "/index.php"
  if( ! buf ) {
    url = dir + "/index.php";
    buf = http_get_cache( item: url, port: port );
    if( ! buf )
      continue;
  }

  # nb: Some versions had that "fi" typo in the title.
  if( buf =~ "<title>GLPI - Auth?enti" && buf =~ "Powered By (Indepnet|Teclib)" ) {
    vers = eregmatch( string: buf, pattern: "GLPI version[ ]+([0-9.]+) ", icase: TRUE );

    if ( ! isnull( vers[1] ) ) {
       version = chomp( vers[1] );
    }
    else {
      # src="/glpi/lib/fuzzy/fuzzy-min.js?v=9.4.3"
      vers = eregmatch( string: buf, pattern: 'src="[^"]+?v=([0-9.]+)"', icase: TRUE );
      if( ! isnull( vers[1] ) )
        version = vers[1];
    }

    set_kb_item( name: string( "www/", port, "/glpi" ), value: string( version, " under " , install ) );
    set_kb_item( name: "glpi/detected", value: TRUE );

    register_and_report_cpe( app: "GLPI",
                             ver: version,
                             concluded: vers[0],
                             base: CPE,
                             expr: "([0-9.]+)",
                             insloc: install,
                             regPort: port,
                             regService: "www",
                             conclUrl: url );

  }
}

exit( 0 );

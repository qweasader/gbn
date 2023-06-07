###############################################################################
# OpenVAS Vulnerability Test
#
# eZ Publish Detection
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (C) 2015 SCHUTZWERK GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111024");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2015-07-25 12:00:00 +0200 (Sat, 25 Jul 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("eZ Publish Detection");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script sends a HTTP
  request to the server and attempts to extract the version from
  the reply.");

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
if( !http_can_host_php( port:port ) ) exit( 0 );

rootInstalled = FALSE;

foreach dir( make_list_unique( "/", "/cms", "/admin", "/siteadmin", "/site_admin", "/backend", http_cgi_dirs( port:port ) ) ) {

  if( rootInstalled ) break;

  install = dir;
  if( dir == "/" ) dir = "";

  buf = http_get_cache( item: dir + "/", port:port );

  if( "eZ Publish" >< buf && "eZ Systems AS" >< buf ) {

    if( dir == "" ) rootInstalled = 1;

    version = 'unknown';
    ver = eregmatch( pattern:'(version|eZ Publish) ([0-9.]+[0-9.]+[0-9.])', string:buf );

    if( ! isnull( ver[2] ) ) version = ver[2];

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:ez:ez_publish:");
    if( isnull( cpe ) )
      cpe = 'cpe:/a:ez:ez_publish';

    set_kb_item( name:"www/" + port + "/ez_publish", value:version );
    set_kb_item( name:"ez_publish/installed", value:TRUE );

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data: build_detection_report( app:"eZ Publish CMS",
                                               version:version,
                                               install:install,
                                               cpe:cpe,
                                               concluded: ver[0]),
                                               port:port);
  }
}

exit(0);

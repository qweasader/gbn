###############################################################################
# OpenVAS Vulnerability Test
#
# Froxlor Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.106035");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2015-08-03 13:44:55 +0700 (Mon, 03 Aug 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Froxlor Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Froxlor Server Management Panel

  The script sends a connection request to the server and attempts to detect Froxlor.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

port = http_get_port( default:80 );

if( ! http_can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/froxlor", http_cgi_dirs( port:port ) ) ) {

  rep_dir = dir;
  if( dir == "/" ) dir = "";

  url = dir + '/index.php';
  res = http_get_cache( item:url, port:port );

  if( "Froxlor Server Management Panel" >< res && ">the Froxlor Team</a>" >< res ) {

    vers = "unknown";
    set_kb_item( name:"www/" + port + "/froxlor", value:vers );
    set_kb_item( name:"froxlor/installed", value:TRUE );

    cpe = 'cpe:/a:froxlor:froxlor';

    register_product( cpe:cpe, location:rep_dir, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Froxlor",
                                              version:vers,
                                              install:rep_dir,
                                              cpe:cpe ),
                                              port:port );
  }
}

exit( 0 );

# Copyright (C) 2010 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902058");
  script_version("2021-09-01T14:04:04+0000");
  script_tag(name:"last_modification", value:"2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)");
  script_tag(name:"creation_date", value:"2010-06-01 15:40:11 +0200 (Tue, 01 Jun 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("OCS Inventory NG Version Detection");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script finds the installed OCS Inventory NG version.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://ocsinventory-ng.org/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

port = http_get_port( default:80 );

if( ! http_can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/ocsreports", "/", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  rcvRes = http_get_cache( item: dir + "/index.php", port:port );

  if( rcvRes =~ "^HTTP/1\.[01] 200" && "OCS Inventory" >< rcvRes ) {

    set_kb_item( name:"ocs_inventory_ng/detected", value:TRUE );

    version = "unknown";

    ver = eregmatch( pattern:"Ver. (<?.>)?([0-9.]+).?(RC[0-9]+)?", string:rcvRes );
    if( ! isnull( ver[2] ) ) {
      if( ! isnull( ver[3] ) ) {
        version = ver[2] + "." + ver[3];
      } else {
        version = ver[2];
      }
    } else {
      url = dir + "/Changes";

      res = http_get_cache( port:port, item:url );
      # Revision history for ocsreports
      # 2.7
      ver = eregmatch( pattern:'Revision history for ocsreports[^0-9]+([0-9.]+[^\r\n]+)', string:res );
      if( ! isnull( ver[1] ) ) {
        version = chomp(ver[1]);
        concUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
      }
    }

    # Server runs only on Linux
    os_register_and_report( os:"Linux", cpe:"cpe:/o:linux:kernel", port:port, desc:"OCS Inventory NG Version Detection", runs_key:"unixoide" );

    cpe = build_cpe( value:version, exp:"^([0-9.]+).?(RC[0-9]+)?", base:"cpe:/a:ocsinventory-ng:ocs_inventory_ng:" );
    if( ! cpe )
      cpe = "cpe:/a:ocsinventory-ng:ocs_inventory_ng";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"OCS Inventory NG",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver[0], concludedUrl: concUrl),
                 port:port );
  }
}

exit( 0 );

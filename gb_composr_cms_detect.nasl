###############################################################################
# OpenVAS Vulnerability Test
#
# Composr CMS Detection
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.107216");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2017-06-12 06:40:16 +0200 (Mon, 12 Jun 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Composr CMS Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installed version of Composr CMS.

  The script tries to detect Composr CMS via HTTP request and to extract its version.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

appPort = http_get_port( default:80 );
if( ! http_can_host_php( port:appPort ) ) exit( 0 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:appPort ) ) ) {

  install = dir;
  if ( dir == "/" ) dir = "";

  url = dir + "/index.php?page=start";

  rcvRes = http_get_cache(item: url, port:appPort);

  if ( rcvRes =~ "^HTTP/1\.[01] 200" && "Powered by Composr" >< rcvRes ) {

    Ver = "unknown";

    tmpVer = eregmatch(pattern:"Powered by Composr version ([0-9.]+),",
                       string:rcvRes);
    if ( ! tmpVer ) {
      tmpVer = eregmatch(pattern:"Powered by Composr version ([0-9.]+) ([A-Z]+[0-9]+),",
                         string:rcvRes);
    }

    if( tmpVer[1] ) {
      Ver = tmpVer[1];
      if ( tmpVer[2] ) Ver += " " + tmpVer[2];
    }

    set_kb_item( name:"composr_cms/installed", value:TRUE );

    cpe = build_cpe( value:Ver, exp:"^([0-9.]+)", base:"cpe:/a:composr:cms:" );
    if ( cpe && tmpVer[2] ) cpe+= tmpVer[2];

    if( ! cpe )
      cpe = 'cpe:/a:composr:cms';

    register_product( cpe:cpe, location:install, port:appPort, service:"www" );

    log_message( data:build_detection_report( app:"Composr_CMS",
                                              version:Ver,
                                              install:install,
                                              cpe:cpe,
                                              concluded:tmpVer[0] ),
                                              port:appPort );
  }
}

exit(0);

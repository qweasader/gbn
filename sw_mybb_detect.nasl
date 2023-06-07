###############################################################################
# OpenVAS Vulnerability Test
#
# MyBB Forum Version Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.111023");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2015-07-20 13:14:40 +0200 (Mon, 20 Jul 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("MyBB Forum Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of a MyBB Forum.");

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
if( ! http_can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/", "/forum", "/forums", "/mybb", "/MyBB", "/board", "/boards", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  res = http_get_cache( item:dir + "/index.php", port:port );

  if( ">MyBB" >< res && ">MyBB Group<" >< res ) {

    vers = "unknown";
    extra = NULL;
    version = eregmatch( pattern:">MyBB ([0-9.]+).?<", string:res );
    if( ! isnull( version[1] ) ) {
      vers = version[1];
    } else {
      version = eregmatch( pattern:"general\.js\?ver=([0-9]+)", string:res );
      if( ! isnull( version[1] ) ) {
        ver = version[1];
        # we get e.g. 1803 for 1.8.3 so strip the 0
        if( strlen( ver ) > 3 && ver[2] == 0 )
          i = 3;
        else
          i = 2;
        vers = ver[0] + '.' + ver[1] + '.' + substr( ver, i );

        # nb: For some unknown reason 1.8.22 had a version ver=1821 in the code above.
        # This is a quick workaround to avoid false positives as we can't differ
        # between both currently.
        if( vers == "1.8.21" ) {
          vers = "1.8.22";
          extra = "Version 1.8.22 had also reported itself as Version 1.8.21.";
          extra += " To avoid false positives 1.8.22 is assumed for this case.";
        }
      }
    }

    set_kb_item( name:"MyBB/installed", value:TRUE );

    cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:mybb:mybb:" );
    if( ! cpe )
      cpe = "cpe:/a:mybb:mybb";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"MyBB Forum",
                                              version:vers,
                                              install:install,
                                              cpe:cpe,
                                              extra:extra,
                                              concluded:version[0] ),
                                              port:port );
  }
}

exit( 0 );

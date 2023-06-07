###############################################################################
# OpenVAS Vulnerability Test
#
# Symphony CMS Version Detection
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801219");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2010-06-11 14:27:58 +0200 (Fri, 11 Jun 2010)");
  script_name("Symphony CMS Detection (HTTP)");

  script_tag(name:"summary", value:"This script finds the running Symphony CMS
  version.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

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
if(!http_can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/", "/cms", "/symphony", http_cgi_dirs( port:port ) ) ) {
  install = dir;
  if( dir == "/" )
    dir = "";

  res = http_get_cache( item:dir + "/symphony/", port:port );
  req2 = http_get( item:dir + "/index.php?mode=administration", port:port );
  res2 = http_keepalive_send_recv( port:port, data:req2 );

  if( ( res =~ "^HTTP/1\.[01] 200" && ( "<title>Login &ndash; Symphony</title>" >< res || "<title>Login &ndash; Symphony CMS</title>" >< res || "<h1>Symphony</h1>" >< res || "<legend>Login</legend>" >< res ) ) ||
      ( res2 =~ "^HTTP/1\.[01] 200" && ( "<title>Login &ndash; Symphony</title>" >< res2 || "<title>Login &ndash; Symphony CMS</title>" >< res2 || "<h1>Symphony</h1>" >< res2 || "<legend>Login</legend>" >< res2 ) ) ) {

    req = http_get( item:dir + "/manifest/logs/main", port:port );
    res = http_keepalive_send_recv( port:port, data:req );

    version = "unknown";

    ver = eregmatch( pattern:"[v|V]ersion: ([0-9.]+)", string:res );
    if( ! isnull( ver[1] ) ) {
      version = ver[1];
    } else {
      # nb: for Symphony 1.7.x
      res = http_get_cache( item:dir + "/README", port:port );
      ver = eregmatch( pattern:"Symphony ([0-9.]+)", string:res );
      if( ! isnull( ver[1] ) ) {
        version = ver[1];
      } else {
        # nb: for Symphony 2.x
        res = http_get_cache( item:dir + "/README.markdown", port:port );
        ver = eregmatch( pattern:"[v|V]ersion: ([0-9.]+)", string:res );
        if( ! isnull( ver[1] ) )
          version = ver[1];
      }
    }

    tmp_version = version + " under " + install;
    set_kb_item( name:"www/" + port + "/symphony", value:tmp_version );
    set_kb_item( name:"symphony/installed", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:symphony-cms:symphony_cms:" );
    if( ! cpe )
      cpe = "cpe:/a:symphony-cms:symphony_cms";

    register_product( cpe:cpe, location:install, port:port, service:"www" );
    log_message( data:build_detection_report( app:"Symphony CMS",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver[0] ),
                                              port:port );
  }
}

exit( 0 );

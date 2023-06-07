# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.900381");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2022-11-08T10:12:11+0000");
  script_tag(name:"last_modification", value:"2022-11-08 10:12:11 +0000 (Tue, 08 Nov 2022)");
  script_tag(name:"creation_date", value:"2009-06-26 07:55:21 +0200 (Fri, 26 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("Mahara Detection");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script detects the installed version of Mahara.");

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

if( ! http_can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/mahara" , "/", "/mahara/htdocs", "/htdocs", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  url = dir + "/index.php";
  res = http_get_cache( item: url, port:port );

  if( "Welcome to Mahara" >!< res && 'content="Mahara' >!< res ) {
    url = dir + "/admin/index.php";
    res = http_get_cache( item: url, port:port );
  }

  if( "Log in to Mahara" >< res || "Welcome to Mahara" >< res || 'content="Mahara' >< res ) {

    set_kb_item( name:"mahara/detected", value:TRUE );
    version = "unknown";

    foreach file( make_list( "/Changelog", "/ChangeLog", "/debian/Changelog" ) ) {
      url2 = dir + file;
      res2 = http_get_cache( item: url2, port:port );
      if( "mahara" >< res2 ) {
        # For greping the version lines
        ver = egrep( pattern:"([0-9.]+[0-9.]+[0-9]+ \([0-9]{4}-[0-9]{2}-[0-9]{2}\))", string:res2 );
        # For matching the first occurring version
        ver = eregmatch( pattern:"^(mahara\ )?\(?(([0-9.]+[0-9.]+[0-9]+)(\~" +
                                 "(beta|alpha)([0-9]))?\-?([0-9])?)\)?([^0-9]"+
                                 "|$)", string:ver );
        # For replacing '~' or '-' with '.'
        ver = ereg_replace( pattern:string("[~|-]"), replace:string("."), string:ver[2] );
      }

      if( !isnull( ver ) ) {
        version = ver;
        concUrl = http_report_vuln_url( port:port, url:url2, url_only:TRUE );
        break;
      }
    }

    if( version == "unknown" ) {
      url2 = dir + "/lib/version.php.temp";
      req = http_get( port:port, item:url2 );
      res2 = http_keepalive_send_recv( port:port, data:req );

      # $config->release = '17.04.2testing';
      ver = eregmatch( pattern:"config->release = '([0-9.]+)", string:res2 );
      if( !isnull(ver[1] ) ) {
        version = ver[1];
        concUrl = http_report_vuln_url( port:port, url:url2, url_only:TRUE );
      } else {
        # <meta name="generator" content="Mahara 15.10 (https://mahara.org)" />
        ver = eregmatch( pattern:'content="Mahara ([0-9.]+)', string: res);
        if( !isnull( ver[1] ) ) {
          version = ver[1];
          concUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
        }
      }
    }

    cpe = build_cpe( value:version, exp:"^([0-9.]+\.[0-9.])\.?([a-z0-9]+)?", base:"cpe:/a:mahara:mahara:" );
    if( !cpe )
      cpe = "cpe:/a:mahara:mahara";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Mahara", version:version, install:install, cpe:cpe,
                                              concluded:ver[0], concludedUrl:concUrl ),
                 port:port );
    exit( 0 );
  }
}

exit( 0 );

###############################################################################
# OpenVAS Vulnerability Test
#
# Sun Java Web Console Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800825");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2022-05-31T20:54:22+0100");
  script_tag(name:"last_modification", value:"2022-05-31 20:54:22 +0100 (Tue, 31 May 2022)");
  script_tag(name:"creation_date", value:"2009-07-09 10:58:23 +0200 (Thu, 09 Jul 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Sun Java Web Console Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 6789);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script detects the installed version of Java Web Console.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

jwcPort = http_get_port( default:6789 );

sndReq1 = http_get( item:"/console/faces/jsp/login/BeginLogin.jsp", port:jwcPort );
rcvRes1 = http_keepalive_send_recv( port:jwcPort, data:sndReq1, bodyonly:FALSE );

if( rcvRes1 =~ "<title>Log In - Sun Java\(TM\) Web Console<" &&
   egrep( pattern:"^HTTP/1\.[01] 200", string:rcvRes1 ) ) {

  jspPath = eregmatch( pattern:"versionWin = window.open\('([a-zA_Z0-9/_.]+)'",
                      string:rcvRes1 );

  sndReq2 = http_get( item:jspPath[1], port:jwcPort );
  rcvRes2 = http_keepalive_send_recv( port:jwcPort, data:sndReq2, bodyonly:FALSE );

  if( rcvRes2 =~ ">Display Product Version - Sun Java\(TM\) Web Console<" &&
     egrep( pattern:"^HTTP/1\.[01] 200", string:rcvRes2 ) ) {

    jwcVer = eregmatch( pattern:">([0-9]\.[0-9.]+)<", string:rcvRes2 );
    if( jwcVer[1] != NULL ) {
      set_kb_item( name:"Sun/JavaWebConsole/Ver", value:jwcVer[1] );
    }
  }

  set_kb_item( name:"Sun/JavaWebConsole/installed", value:TRUE );

  cpe = build_cpe(value:jwcVer[1], exp:"^([0-9.]+)", base:"cpe:/a:sun:java_web_console:");
  if( isnull( cpe ) )
    cpe = 'cpe:/a:sun:java_web_console';

  register_product( cpe:cpe, location:jwcPort + '/tcp', port:jwcPort, service:"www" );

  log_message( data: build_detection_report(app:"Sun Java Web Console",
                                           version:jwcVer[1],
                                           install:jwcPort + '/tcp',
                                           cpe:cpe,
                                           concluded: jwcVer[1] ),
                                           port:jwcPort );
}

exit( 0 );

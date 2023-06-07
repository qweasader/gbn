###############################################################################
# OpenVAS Vulnerability Test
#
# IBM Open Admin Tool Version Detection
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802158");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2011-09-14 16:05:49 +0200 (Wed, 14 Sep 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("IBM Open Admin Tool Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script finds the installed IBM Open Admin Tool version.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port( default:8080 );

if( ! http_can_host_php( port:port ) )
  exit( 0 );

sndReq = http_get( item:"/openadmin/index.php?act=help&do=aboutOAT", port:port );
rcvRes = http_keepalive_send_recv( port:port, data:sndReq );

if( ">OpenAdmin Tool" >< rcvRes || "> OpenAdmin Tool Community Edition <" >< rcvRes ) {

  version = "unknown";
  install = "/";

  ver = eregmatch( pattern:">Version:.*[^\n]", string:rcvRes );
  ver = eregmatch( pattern:"([0-9.]+)", string:ver[0] );
  if( ver[1] != NULL ) version = ver[1];

  set_kb_item(name: "ibm_openadmin/installed", value: TRUE);
  set_kb_item( name:"www/" + port + "/IBM/Open/Admin/Tool", value:version );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:ibm:openadmin_tool:" );
  if( isnull( cpe ) )
    cpe = 'cpe:/a:ibm:openadmin_tool';

  register_product( cpe:cpe, location:install, port:port, service:"www" );

  log_message( data:build_detection_report( app:"IBM Open Admin Tool",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:ver[0] ),
               port:port );
}

exit( 0 );

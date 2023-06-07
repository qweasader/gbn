###############################################################################
# OpenVAS Vulnerability Test
#
# Barracuda Web Filter Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105286");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2015-06-03 15:28:32 +0200 (Wed, 03 Jun 2015)");
  script_name("Barracuda Web Filter Detection (HTTP)");

  script_tag(name:"summary", value:"The script sends a connection
  request to the server and attempts to extract the version number
  from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("BarracudaHTTP/banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:80 );
banner = http_get_remote_headers( port:port );

if( "BarracudaHTTP" >!< banner ) exit( 0 );

url = '/cgi-mod/index.cgi';
req = http_get(item:url, port:port);
buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

if( "Web Filter: Welcome" >!< buf ) exit( 0 );

set_kb_item(name:"barracuda_web_filter/installed",value:TRUE);
cpe = ' cpe:/a:barracuda:web_filter';

version = eregmatch( pattern:'/barracuda.css\\?v=([0-9.]+)">', string:buf );
if( isnull( version[1] ) ) {
  url = "/cgi-mod/view_help.cgi";
  req = http_get(item:url, port:port);
  buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

  version = eregmatch( pattern:'/barracuda.css\\?v=([0-9.]+)">', string:buf );
}

if( ! isnull( version[1] ) ) {
  vers = version[1];
  cpe += ':' + vers;
  set_kb_item( name:"barracuda_web_filter/version", value:vers );
}

register_product( cpe:cpe, location:'/cgi-mod/', port:port, service:"www" );

log_message( data: build_detection_report( app:"Barracuda Web Filter",
                                           version:vers,
                                           install:'/cgi-mod/',
                                           cpe:cpe,
                                           concluded: version[0] ),
             port:port );

exit(0);


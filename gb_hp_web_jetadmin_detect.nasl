###############################################################################
# OpenVAS Vulnerability Test
#
# HP Web Jetadmin Remote Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.812515");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-02-20 14:56:22 +0530 (Tue, 20 Feb 2018)");
  script_name("HP Web Jetadmin Remote Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8000);
  script_mandatory_keys("Jetadmin/banner");

  script_tag(name:"summary", value:"Detects the installed version of
  HP Web Jetadmin.

  This script sends an HTTP GET request and tries to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:8000 );

banner = http_get_remote_headers( port:port );
if( ! banner )
  exit( 0 );

if( ! concl = egrep(string:banner, pattern:"Server: HP Web Jetadmin", icase:TRUE ) )
  exit( 0 );

concl = chomp( concl );
vers = "unknown";
install = port + "/tcp";

# Server: HP Web Jetadmin/2.0.47
# Server: HP Web Jetadmin 10.4.99821
version = eregmatch( string:banner, pattern: "Server: HP Web Jetadmin\/? ?([0-9.]+)", icase:TRUE );
if( ! isnull( version[1] ) ) {
  vers = version[1];
  concl = version[0];
}

set_kb_item( name:"HpWebJetadmin/installed", value:TRUE );
set_kb_item( name:"www/" + port + "/HP_Web_Jetadmin", value:vers );

cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:hp:web_jetadmin:" );
if( ! cpe )
  cpe = "cpe:/a:hp:web_jetadmin";

register_product( cpe:cpe, location:install, port:port, service:"www" );

log_message( data:build_detection_report( app:"HP Web Jetadmin",
                                          version:vers,
                                          install:install,
                                          cpe:cpe,
                                          concluded:concl ),
                                          port:port );

exit( 0 );

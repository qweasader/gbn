###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft SQL TCP/IP listener is running
#
# Authors:
# Nicolas Gregoire <ngregoire@exaprobe.com>
# Adapted from mssql_blank_password.nasl
#
# Copyright:
# Copyright (C) 2005 Nicolas Gregoire
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.10144");
  script_version("2022-08-02T10:11:24+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-08-02 10:11:24 +0000 (Tue, 02 Aug 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_name("Microsoft SQL Server (MSSQL) Detection (TCP/IP Listener)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Nicolas Gregoire");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "find_service2.nasl");
  script_require_ports("Services/unknown", 1433);

  script_tag(name:"summary", value:"Microsoft SQL Server (MSSQL) detection based on an exposed
  TCP/IP listener.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("byte_func.inc");
include("host_details.inc");
include("os_func.inc");
include("mssql.inc");
include("port_service_func.inc");

port = unknownservice_get_port( default:1433 );

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

payload = raw_string( 0x00, 0x00, 0x1a, 0x00, 0x06, 0x01, 0x00, 0x20,
                      0x00, 0x01, 0x02, 0x00, 0x21, 0x00, 0x01, 0x03,
                      0x00, 0x22, 0x00, 0x04, 0x04, 0x00, 0x26, 0x00,
                      0x01, 0xff, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );

len = strlen( payload );

# TDS7 pre-login message (http://msdn.microsoft.com/en-us/library/dd357559.aspx)
req = raw_string( 0x12, 0x01 ) +
      mkword( len + 8 ) +
      raw_string( 0x00, 0x00, 0x00, 0x00 ) +
      payload;

send( socket:soc, data:req );
buf = recv( socket:soc, length:4096 );
close( soc );

if( ! buf )
  exit( 0 );

len = strlen( buf );
if( len < 18 )
  exit( 0 );

res_type = ord( buf[0] );
if( res_type != 4 )
  exit( 0 );

pos = 8;

if( ord( buf[ pos ] ) != 0 )
  exit( 0 );

off  = getword( blob:buf, pos:pos + 1 );
blen = getword( blob:buf, pos:pos + 3 );
pos += off;

if( blen < 6 || ( pos + 6 ) > strlen( buf ) )
  exit( 0 );

version = ord( buf[ pos ] ) + "." + ord( buf[ pos + 1 ] ) + "." + getword( blob:buf, pos:pos + 2 ) + "." + getword( blob:buf, pos:pos + 4 );
service_register( port:port, proto:"mssql" );

os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", port:port, desc:"Microsoft SQL Server (MSSQL) Detection (TCP/IP Listener)", runs_key:"windows" );

set_kb_item( name:"OpenDatabase/found", value:TRUE );

set_kb_item( name:"microsoft/sqlserver/detected", value:TRUE );
set_kb_item( name:"microsoft/sqlserver/" + port + "/detected", value:TRUE );
set_kb_item( name:"microsoft/sqlserver/tcp_listener/detected", value:TRUE );
set_kb_item( name:"microsoft/sqlserver/tcp_listener/" + port + "/detected", value:TRUE );

releaseName = mssql_get_rel_name( version:version );

install = port + "/tcp";

if( releaseName ) {
  set_kb_item( name:"microsoft/sqlserver/releasename", value:releaseName );
  set_kb_item( name:"microsoft/sqlserver/" + port + "/releasename", value:releaseName );

  # nb: The one below should be eventually dropped in the future once all VTs are using the previous new KB key.
  set_kb_item( name:"MS/SQLSERVER/" + port + "/releasename", value:releaseName );
}

cpe = "cpe:/a:microsoft:sql_server";

if( releaseName != "unknown release name" ) {
  cpe_rel = tolower( releaseName );
  cpe_rel = str_replace( string:cpe_rel, find:" ", replace:":" );
  cpe += ":" + cpe_rel;
}

vers = eregmatch( pattern:"^([0-9.]+)", string:version );
if( vers[1] )
  set_kb_item( name:"microsoft/sqlserver/" + port + "/version", value:vers[1] );

register_product( cpe:cpe, location:install, port:port, service:"mssql" );

log_message( data:build_detection_report( app:"Microsoft SQL Server (MSSQL) " + releaseName,
                                          version:version,
                                          install:install,
                                          cpe:cpe ),
             port:port );

exit( 0 );

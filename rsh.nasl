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
  script_oid("1.3.6.1.4.1.25623.1.0.108478");
  script_version("2021-04-16T08:08:22+0000");
  script_tag(name:"last_modification", value:"2021-04-16 08:08:22 +0000 (Fri, 16 Apr 2021)");
  script_tag(name:"creation_date", value:"2009-03-26 19:23:59 +0100 (Thu, 26 Mar 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("rsh Service Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service1.nasl");
  script_require_ports("Services/rsh", "Services/unknown", 514);

  script_tag(name:"summary", value:"Checks if the remote host is running a rsh service.

  Note: The reporting takes place in a separate VT 'rsh Unencrypted Cleartext Login'
  (OID: 1.3.6.1.4.1.25623.1.0.100080).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("list_array_func.inc");
include("dump.inc");

data = string( '0\0', "root", '\0', "root", '\0', 'id\0' ); #  Found in http://cpansearch.perl.org/src/ASLETT/Net-Rsh-0.05/Rsh.pm

ports = make_list( 514 );

unkn_ports = unknownservice_get_ports( default_port_list:make_list( 514 ) );
if( unkn_ports && is_array( unkn_ports ) )
  ports = make_list( ports, unkn_ports );

rsh_ports = service_get_ports( default_port_list:make_list( 514 ), proto:"rsh" );
if( rsh_ports && is_array( rsh_ports ) )
  ports = make_list( ports, rsh_ports );

ports = make_list_unique( ports );

foreach port( ports ) {

  found = FALSE;

  if( ! get_port_state( port ) )
    continue;

  if( ! soc = open_priv_sock_tcp( dport:port ) )
    continue;

  send( socket:soc, data:data );
  buf = recv( socket:soc, length:8192 );
  close( soc );

  if( ! buf )
    continue;

  # TODO/TBD: Add additional detection pattern?
  if( "Permission denied" >< buf ) {
    found = TRUE;
    report = "The rsh service is not allowing connections from this host.";
  } else if ( egrep( pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:bin2string( ddata:buf ) ) ) {
    found = TRUE;
    set_kb_item( name:"rsh/login_from", value:"root" );
    set_kb_item( name:"rsh/login_to", value:"root" );
    report = "The rsh service is misconfigured so it is allowing conntections without a password or with default root:root credentials.";
  } else if( "getnameinfo: Temporary failure in name resolution" >< buf ) {
    found = TRUE;
    report = "The rsh service currently has issues with name resolution and is not allowing connections from this host.";
  }

  if( found ) {
    set_kb_item( name:"rsh/detected", value:TRUE );
    set_kb_item( name:"rsh/" + port + "/detected", value:TRUE );
    set_kb_item( name:"rsh/" + port + "/service_report", value:report );
    service_register( port:port, proto:"rsh", message:"A rsh service seems to be running on this port." );
    log_message( port:port, data:"A rsh service is running at this port." );
  }
}

exit( 0 );
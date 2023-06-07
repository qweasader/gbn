###############################################################################
# OpenVAS Vulnerability Test
#
# Description: Kerio Personal Firewall Admin Service
#
# Authors:
# Javier Munoz Mellid <jm@udc.es>
#
# Copyright:
# Copyright (C) 2005 Secure Computer Group. University of A Coruna
# Copyright (C) 2005 Javier Munoz Mellid
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.18183");
  script_version("2020-11-10T15:30:28+0000");

  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"last_modification", value:"2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");

  script_name("Kerio Personal Firewall Admin Service");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Javier Munoz Mellid");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 44334);

  script_tag(name:"summary", value:"The remote host appears to be running the Kerio Personal Firewall
  Admin service on this port. It is recommended that this port is not
  reachable from the outside.

  Also, make sure that the use of this software is done in accordance with
  your corporate security policy.");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

CPE = "cpe:/a:kerio:personal_firewall:";

include( "host_details.inc" );
include( "cpe.inc" );
include( "port_service_func.inc" );

function kpf_isWeakAdminProtocol( port ) {

  local_var port, soc, vuln, s, r, i;

  soc = open_sock_tcp( port );

  if( ! soc ) return FALSE;

  vuln = 1;

  for( i = 0; i < 5; i++ ) {

    s = raw_string( 0x01 );
    send( socket:soc, data:s );

    if( ! soc ) vuln = 0;

    r = recv( socket:soc, length:16 );

    if( isnull( r ) || ( strlen( r ) != 2 ) || ( ord( r[0] ) != 0x01 ) || ( ord( r[1] ) != 0x00 ) ) {
      vuln = 0;
      break;
    }
  }

  close( soc );

  if( vuln ) {
    return TRUE;
  } else {
    return FALSE;
  }
}

port = unknownservice_get_port( default:44334 ); # default kpf port

if( kpf_isWeakAdminProtocol( port:port ) ) {
  set_kb_item( name:"kpf_admin_port/detected", value:TRUE );
  service_register( port:port, proto:"kerio" );
  register_and_report_cpe( app:"Kerio Personal Firewall",
                           ver:"unknown",
                           base:CPE,
                           insloc:port + "/tcp",
                           regPort:port,
                           regProto:"tcp" );
}

exit( 0 );

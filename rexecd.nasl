###############################################################################
# OpenVAS Vulnerability Test
#
# rexec Passwordless / Unencrypted Cleartext Login
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.113763");
  script_version("2020-11-10T15:30:28+0000");
  script_tag(name:"last_modification", value:"2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)");
  script_tag(name:"creation_date", value:"2009-04-08 12:09:59 +0200 (Wed, 08 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("rexec Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service6.nasl");
  script_require_ports("Services/rexec", 512);

  script_tag(name:"summary", value:"This remote host is running a rexec service.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include( "host_details.inc" );
include( "port_service_func.inc" );

# sending a too long username. Without that too long username i did
# not get any response from rexecd.
for( i = 0; i < 260; i++ ) {
  username += string("x");
}

rexecd_string = string( raw_string( 0 ), username, raw_string( 0 ), "xxx", raw_string( 0 ), "id", raw_string( 0 ) );

port = service_get_port( proto:"rexec", default:512 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

send( socket:soc, data:rexecd_string );
buf = recv_line( socket:soc, length:4096 );
close( soc );
if( isnull( buf ) ) exit( 0 );

# TBD: ord( buf[0] ) == 1 || was previously tested here but
# that is to prone for false positives against all unknown ports...
if( "too long" >< buf || "Where are you?" >< buf ) {
  set_kb_item( name:"rexec/detected", value:TRUE );
  set_kb_item( name:"rexec/port", value:port );
  service_register( port:port, proto:"rexec", message:"A rexec service seems to be running on this port." );
  if( "Where are you?" >< buf ) {
    report = "The rexec service is not allowing connections from this host.";
  }
  log_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

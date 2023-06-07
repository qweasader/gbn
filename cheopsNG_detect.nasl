###############################################################################
# OpenVAS Vulnerability Test
#
# Cheops NG Agent Detection
#
# Authors:
# Michel Arboi <mikhail@nessus.org>
#
# Copyright:
# Copyright (C) 2006 Michel Arboi
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
  script_oid("1.3.6.1.4.1.25623.1.0.20160");
  script_version("2022-05-10T07:26:01+0000");
  script_tag(name:"last_modification", value:"2022-05-10 07:26:01 +0000 (Tue, 10 May 2022)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Cheops NG Agent Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2006 Michel Arboi");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports(2300);

  script_xref(name:"URL", value:"http://cheops-ng.sourceforge.net/");

  script_tag(name:"summary", value:"The remote host is running a Cheops NG agent.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");

port = 2300;
if( ! get_port_state( port ) )
  exit( 0 );

if( service_is_known( port:port ) )
  exit( 0 );

m1 = '\x00\x00\x00\x14\x00\x0c\x00\x04\x00\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00';
m2 = '\x00\x00\x00\x20\x00\x0c\x00\x02\x00\x00\x00\x00\x01\x00\x00\x7f\x01\x00\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\xb8\xdf\x0d\x08';

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

send( socket:soc, data:m1 );
r = recv( socket:soc, length:512 );
if( strlen( r ) > 0 ) {
  if( substr( r, 0, 7 ) == '\x00\x00\x00\x10\x00\x0c\x00\x6c' ) {
    log_message( port:port );
    service_register( port:port, proto:"cheops-ng" );
    set_kb_item( name:"cheopsNG/password", value:port );
  }
  close( soc );
  exit( 0 );
}

send( socket:soc, data:m2 );
r = recv( socket:soc, length:512 );
l = strlen( r );
if( l >= 8 && substr( r, 0, 2 ) == '\0\0\0' && '\x01\x00\x00\x7f' >< r ) {
  log_message( port:port );
  service_register( port:port, proto:"cheops-ng" );
  set_kb_item( name:"cheopsNG/unprotected", value:port );
}

close( soc );
exit( 0 );

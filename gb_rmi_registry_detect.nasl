# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105839");
  script_version("2022-12-21T10:12:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-12-21 10:12:09 +0000 (Wed, 21 Dec 2022)");
  script_tag(name:"creation_date", value:"2016-08-01 09:40:35 +0200 (Mon, 01 Aug 2016)");
  script_name("RMI Registry Service Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 1099);

  script_tag(name:"summary", value:"Detection of a Remote Method Invocation (RMI) registry
  service.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("byte_func.inc");
include("port_service_func.inc");

port = unknownservice_get_port( default:1099 );

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

req = "JRMI" + raw_string( 0x00, 0x02, 0x4b );

send( socket:soc, data:req );
res = recv( socket:soc, length:128, min:7 );
close( soc );

if( ! res || hexstr( res[0] ) != "4e" || ( getword( blob:res, pos:1 ) + 7 ) != strlen( res ) )
  exit( 0 );

set_kb_item( name:"rmi_registry/detected", value:TRUE );

service_register( port:port, proto:"rmi_registry" );
log_message( port:port, data:"A RMI registry service is running at this port");
exit( 0 );

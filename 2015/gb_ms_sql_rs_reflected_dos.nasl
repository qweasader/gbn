# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105187");
  script_version("2021-09-29T05:25:13+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("MS SQL Server Resolution Service Amplification Reflected DRDoS");
  script_tag(name:"last_modification", value:"2021-09-29 05:25:13 +0000 (Wed, 29 Sep 2021)");
  script_tag(name:"creation_date", value:"2015-01-26 13:45:36 +0100 (Mon, 26 Jan 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("mssql_ping.nasl", "global_settings.nasl");
  script_mandatory_keys("MSSQL/UDP/Ping", "keys/is_public_addr");

  script_xref(name:"URL", value:"http://kurtaubuchon.blogspot.de/2015/01/mc-sqlr-amplification-ms-sql-server.html");

  script_tag(name:"impact", value:"Successfully exploiting this vulnerability allows attackers to
  cause denial-of-service conditions against remote hosts.");

  script_tag(name:"vuldetect", value:"Send a request with a single byte and check the length of the
  response.

  Note:

  This VT is only reporting a vulnerability if the target system / service is accessible from a
  public WAN (Internet) / public LAN.

  A configuration option 'Network type' to define if a scanned network should be seen as a public
  LAN can be found in the preferences of the following VT:

  Global variable settings (OID: 1.3.6.1.4.1.25623.1.0.12288)");

  script_tag(name:"solution", value:"Restrict access to this port.");

  script_tag(name:"summary", value:"The remote MS SQL Server allows distributed reflection and
  amplification (DRDoS) attacks.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("network_func.inc");

if( ! is_public_addr() )
  exit( 0 );

port = 1434;

soc = open_sock_udp( port );
if( ! soc ) exit(0);

byte = raw_string( 0x02 );

send( socket:soc, data:byte );
recv = recv( socket:soc, length:4096 );

close( soc );

if( recv && strlen( recv ) > 50 ) {
  report = 'By sending a request with a single byte, we received a response of ' +  strlen( recv ) + ' bytes.';
  security_message( port:port, proto:"udp", data:report );
  exit( 0 );
}

exit( 99 );
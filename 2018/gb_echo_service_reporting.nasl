# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100075");
  script_version("2021-10-20T09:03:29+0000");
  script_tag(name:"last_modification", value:"2021-10-20 09:03:29 +0000 (Wed, 20 Oct 2021)");
  script_tag(name:"creation_date", value:"2018-10-23 14:01:33 +0200 (Tue, 23 Oct 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-1999-0635");
  script_name("echo Service Reporting (TCP + UDP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Useless services");
  script_dependencies("echo.nasl", "echo_udp.nasl");
  script_mandatory_keys("echo_tcp_udp/detected");

  script_tag(name:"solution", value:"Disable the echo Service.");

  script_tag(name:"summary", value:"An echo Service is running at this Host via TCP and/or UDP.");

  script_tag(name:"insight", value:"The echo service is an Internet protocol defined in RFC 862. It
  was originally proposed for testing and measurement of round-trip times in IP networks. While
  still available on most UNIX-like operating systems, testing and measurement is now performed with
  the Internet Control Message Protocol (ICMP), using the applications ping and traceroute.

  Remark: NIST don't see 'configuration issues' as software flaws so the referenced CVE has a
  severity of 0.0. The severity of this VT has been raised by Greenbone to still report a
  configuration issue on the target.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("port_service_func.inc");

default_ports = make_list( 7 );

tcp_ports = service_get_ports( default_port_list:default_ports, proto:"echo" );
foreach tcp_port( tcp_ports ) {
  if( ! get_kb_item( "echo_tcp/" + tcp_port + "/detected" ) )
    continue;

  VULN = TRUE;
  security_message( port:tcp_port );
}

udp_ports = service_get_ports( default_port_list:default_ports, proto:"echo", ipproto:"udp" );
foreach udp_port( udp_ports ) {
  if( ! get_kb_item( "echo_udp/" + udp_port + "/detected" ) )
    continue;

  VULN = TRUE;
  security_message( port:udp_port, protocol:"udp" );
}

if( VULN )
  exit( 0 );
else
  exit( 99 );
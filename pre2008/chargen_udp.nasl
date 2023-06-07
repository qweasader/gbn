###############################################################################
# OpenVAS Vulnerability Test
#
# Check for Chargen Service (UDP)
#
# Authors:
# Mathieu Perrin <mathieu@tpfh.org>
#
# Copyright:
# Copyright (C) 1999 Mathieu Perrin
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
  script_oid("1.3.6.1.4.1.25623.1.0.108030");
  script_version("2021-10-20T09:03:29+0000");
  script_tag(name:"last_modification", value:"2021-10-20 09:03:29 +0000 (Wed, 20 Oct 2021)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-1999-0103");
  script_name("Check for Chargen Service (UDP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 1999 Mathieu Perrin");
  script_family("Useless services");
  script_dependencies("gb_chargen_detect_udp.nasl");
  script_mandatory_keys("chargen/udp/detected");

  script_tag(name:"summary", value:"The remote host is running a 'chargen' service.");

  script_tag(name:"insight", value:"When contacted, chargen responds with some random characters
  (something like all the characters in the alphabet in a row). When contacted via UDP, it will
  respond with a single UDP packet.

  The purpose of this service was to mostly to test the TCP/IP protocol by itself, to make sure that
  all the packets were arriving at their destination unaltered. It is unused these days, so it is
  suggested you disable it, as an attacker may use it to set up an attack against this host, or
  against a third party host using this host as a relay.

  Remark: NIST don't see 'configuration issues' as software flaws so the referenced CVE has a
  severity of 0.0. The severity of this VT has been raised by Greenbone to still report a
  configuration issue on the target.");

  script_tag(name:"solution", value:"- Under Unix systems, comment out the 'chargen' line in
  /etc/inetd.conf and restart the inetd process

  - Under Windows systems, set the following registry keys to 0 :

  HKLM\System\CurrentControlSet\Services\SimpTCP\Parameters\EnableTcpChargen

  HKLM\System\CurrentControlSet\Services\SimpTCP\Parameters\EnableUdpChargen

  Then launch cmd.exe and type :

  net stop simptcp

  net start simptcp

  To restart the service.");

  script_tag(name:"impact", value:"An easy attack is 'ping-pong' in which an attacker spoofs a
  packet between two machines running chargen. This will cause them to spew characters at each
  other, slowing the machines down and saturating the network.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("port_service_func.inc");

port = service_get_port( default:19, proto:"chargen", ipproto:"udp" );

if( get_kb_item( "chargen/udp/" + port + "/detected" ) ) {
  security_message( port:port, proto:"udp" );
  exit( 0 );
}

exit( 99 );
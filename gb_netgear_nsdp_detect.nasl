# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108696");
  script_version("2021-05-27T07:09:59+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-05-27 07:09:59 +0000 (Thu, 27 May 2021)");
  script_tag(name:"creation_date", value:"2019-12-19 10:27:28 +0000 (Thu, 19 Dec 2019)");
  script_name("Netgear Switch Discovery Protocol (NSDP) Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_dependencies("global_settings.nasl");
  script_mandatory_keys("keys/islocalnet");
  script_exclude_keys("keys/islocalhost", "keys/TARGET_IS_IPV6");
  # nb: Don't add script_require_udp_ports and/or get_udp_port_state as we're not contacting the
  # target directly and the ports are not open/listening on the target devices.

  script_xref(name:"URL", value:"https://en.wikipedia.org/wiki/Netgear_NSDP");

  script_tag(name:"summary", value:"Detection of devices supporting the Netgear Switch
  Discovery Protocol (NSDP).");

  script_tag(name:"vuldetect", value:"Sends various NSDP discovery requests to the local
  broadcast address and attempts to determine if the remote host supports the NSDP.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("port_service_func.inc");
include("dump.inc");
include("host_details.inc");
include("version_func.inc");

if( islocalhost() || TARGET_IS_IPV6() )
  exit( 0 );

# Only GOS/GVM 20.8.0+ is shipping the required allow_broadcast functionality
# in send_packet().
# TODO: Remove once all GOS/GVM versions < 20.8.0 are EOL.
if( version_is_less( version:OPENVAS_VERSION, test_version:"20.8.0" ) )
  exit( 0 );

srcaddr = this_host();
targetaddr = get_host_ip();
dstaddr = "255.255.255.255";
report = "A service supporting the Netgear Switch Discovery Protocol (NSDP) seems to be running on this port.";

# The following requests captured from a NETGEAR ProSAFE Plus Configuration Utility
# connecting to a GS108Ev3. Protocol description is available at:
# https://en.wikipedia.org/wiki/Netgear_NSDP
#
# nb: This tools seems to send out different requests to the remote device
# to see on which of the requests the device is responding to.
# nb2: Some of the packets are shown in Wireshark as "ADwin" but this is just wrong.
reqs = make_list();

# From older version of the config utility (2.6.x) but only one request was captured.
reqs[0] = raw_string( 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x74, 0xd4, 0x35, 0x80, 0x4b, 0x2e, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x44, 0x4e, 0x53, 0x44, 0x50, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
                      0x00, 0x05, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00,
                      0x00, 0x0b, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00,
                      0x00, 0x0f, 0x00, 0x00, 0x74, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00 );

# This two requests are from version 2.7.7 of the config utility.
# The first request is also sent out twice so doing the same here.
reqs[1] = raw_string( 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x74, 0xd4, 0x35, 0xe7, 0x2e, 0x23, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x39, 0x4e, 0x53, 0x44, 0x50, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
                      0x00, 0x05, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00,
                      0x00, 0x0b, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00,
                      0x00, 0x0f, 0x00, 0x00, 0x74, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00 );
reqs[2] = reqs[1];

reqs[3] = raw_string( 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x74, 0xd4, 0x35, 0xe7, 0x2e, 0x23, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1b, 0x4e, 0x53, 0x44, 0x50, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
                      0x00, 0x05, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00,
                      0x00, 0x0b, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00,
                      0x00, 0x0f, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00 );

# As used by nsdtool
reqs[4] = raw_string( 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x27, 0x47, 0x56, 0x16, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x4e, 0x53, 0x44, 0x50, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
                      0x00, 0x05, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00,
                      0x00, 0x0b, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00,
                      0x00, 0x0f, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00 );

foreach dstport( make_list( 63321, 63322, 63323, 63324 ) ) {

  # nb: Short tests have shown that srcport is always dstport -1 (At least as used by the config utility)
  srcport = dstport - 1;
  filter = "udp and src host " + targetaddr + " and dst host " + srcaddr + " and dst port " + srcport + " and src port " + dstport;

  foreach req( reqs ) {

    req_len = strlen( req ) + 8;

    ip_pkt = forge_ip_packet( ip_hl:5, ip_v:4, ip_tos:0, ip_len:20, ip_id:rand(), ip_off:0, ip_ttl:128, ip_p:IPPROTO_UDP, ip_src:srcaddr, ip_dst:dstaddr );
    udp_pkt = forge_udp_packet( ip:ip_pkt, uh_sport:srcport, uh_dport:dstport, uh_ulen:req_len, data:req );

    res = send_packet( udp_pkt, pcap_active:TRUE, pcap_filter:filter, allow_broadcast:TRUE );
    if( res ) {
      data = get_udp_element( udp:res, element:"data" );
      if( data && "NSDP" >< data ) {
        set_kb_item( name:"netgear/nsdp/detected", value:TRUE );
        service_register( port:dstport, ipproto:"udp", proto:"nsdp", message:report );
        log_message( port:dstport, proto:"udp", data:report );
        break;
      }
    }
  }
}

exit( 0 );

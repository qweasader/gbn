###############################################################################
# OpenVAS Vulnerability Test
#
# Port TCP:0 Open
#
# Authors:
# Michel Arboi <mikhail@nessus.org>
#
# Copyright:
# Copyright (C) 2005 Michel Arboi
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
  script_oid("1.3.6.1.4.1.25623.1.0.18164");
  script_version("2022-04-12T13:59:02+0000");
  script_tag(name:"last_modification", value:"2022-04-12 13:59:02 +0000 (Tue, 12 Apr 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Port TCP:0 Open");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Michel Arboi");
  script_family("Malware");
  script_dependencies("find_service.nasl", "global_settings.nasl");
  script_exclude_keys("keys/islocalhost", "keys/TARGET_IS_IPV6");

  script_xref(name:"URL", value:"http://www.simovits.com/trojans/tr_data/y2814.html");
  script_xref(name:"URL", value:"http://www.bizsystems.com/downloads/labrea/localTrojans.pl");

  script_tag(name:"solution", value:"Check your system.");

  script_tag(name:"summary", value:"TCP port 0 is open on the remote host. This is highly suspicious
  as this TCP port is reserved and should not be used. This might be a backdoor (REx).");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

if(islocalhost() || TARGET_IS_IPV6())
  exit(0);

saddr = this_host();
daddr = get_host_ip();
sport = rand() % 64512 + 1024;
dport = 0;
filter = strcat('src port ', dport, ' and src host ', daddr, ' and dst port ', sport, ' and dst host ', saddr);

ip = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:0, ip_off:0, ip_len:20,
                     ip_p:IPPROTO_TCP, ip_ttl:0x40,
                     ip_src:saddr);
tcp = forge_tcp_packet(ip:ip, th_sport:sport, th_dport:dport,
                       th_flags:TH_SYN, th_seq:rand(), th_ack:0,
                       th_x2:0, th_off:5, th_win:512, th_urp:0);

for(i = 0; i < 3; i++) {

  reply = send_packet(pcap_active:TRUE, pcap_filter:filter, pcap_timeout:2, tcp);
  if(reply) {

    flags = get_tcp_element(tcp:reply, element:"th_flags");
    if((flags & TH_SYN) && (flags & TH_ACK))
      security_message(port:0); # Scanner API cannot really handle this
    exit(0);
  }
}

exit(0);

# SPDX-FileCopyrightText: 2003 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# References:
# RFC 792 Internet Control Message Protocol
# RFC 791 Internet Protocol
#
# How to drop source routed packets.
# On Linux 2.4:
#  sysctl -w net.ipv4.conf.all.accept_source_route=0

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11834");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_name("Source Routed Packets");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2003 Michel Arboi");
  script_family("Denial of Service");
  script_dependencies("secpod_open_tcp_ports.nasl", "global_settings.nasl");
  script_mandatory_keys("TCP/PORTS");
  script_exclude_keys("keys/islocalhost", "keys/TARGET_IS_IPV6");

  script_tag(name:"solution", value:"Drop source routed packets on this host or on other ingress
  routers or firewalls.");

  script_tag(name:"summary", value:"The remote host accepts loose source routed IP packets.
  The feature was designed for testing purpose.");

  script_tag(name:"impact", value:"An attacker may use it to circumvent poorly designed IP filtering
  and exploit another flaw. However, it is not dangerous by itself.

  Worse, the remote host reverses the route when it answers to loose
  source routed TCP packets. This makes attacks easier.");

  script_tag(name:"qod_type", value:"remote_probe");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("misc_func.inc");
include("port_service_func.inc");

if(islocalhost())
  exit(0); # Don't test the loopback interface

if(TARGET_IS_IPV6())
  exit(0);

srcaddr = this_host();
dstaddr = get_host_ip();
n = 3; # Number of tries

# Loose source & record route (LSRR)
# Currently, insert_ip_options() is buggy
lsrr = raw_string(131, # LSRR
                  3,   # Length
                  4,   # Pointer
                  0);  # Padding

dstport = tcp_get_first_open_port();

if(dstport) {

  srcport = rand() % 64512 + 1024;

  ip = forge_ip_packet(ip_hl:6, ip_v:4, ip_tos:0, ip_id:rand() % 65536,
                       ip_off:0, ip_ttl:0x40, ip_p:IPPROTO_TCP, ip_src:srcaddr,
                       data:lsrr);
  tcp = forge_tcp_packet(ip:ip, th_sport:srcport, th_dport:dstport,
                         th_flags:TH_SYN, th_seq:rand(), th_ack:0, th_off:5, th_win:512);

  filter = strcat("src host ", dstaddr, " and dst host ", srcaddr, " and tcp and tcp src port ", dstport, " and tcp dst port ", srcport);
  r = NULL;
  for(i = 0; i < n && ! r; i++)
    r = send_packet(tcp, pcap_active:TRUE, pcap_filter:filter);

  if(i < n) {

    # No need to associate this flaw with a specific port
    set_kb_item(name:"Host/accept_lsrr", value:TRUE);
    ihl = 4 * get_ip_element(ip:r, element:"ip_hl");
    if(ihl > 20) {

      opt = substr(ip, 20, ihl-1);
      len = ihl - 21;
      for(i = 0; i < len;) {
        if(opt[i] == '\x83') {
          set_kb_item(name:"Host/tcp_reverse_lsrr", value:TRUE);
          security_message(port:0, proto:"tcp");
          exit(0);
        }
        if(opt[i] == 1)
          i ++;
        else
          i += ord(opt[i+1]);
      }
    }
    #set_kb_item(name:"Host/tcp_reverse_lsrr", value:FALSE);
    security_message(port:0, proto:"tcp");
  }
  exit(0); # Don't try again with ICMP
}

# We cannot use icmp_seq to identifies the datagrams because
# forge_icmp_packet() is buggy. So we use the data instead
filter = strcat("icmp and icmp[0]=0 and src ", dstaddr, " and dst ", srcaddr);

d = rand_str(length:8);
for(i = 0; i < 8; i++)
  filter = strcat(filter, " and icmp[", i+8, "]=", ord(d[i]));

ip = forge_ip_packet(ip_hl:6, ip_v:4, ip_tos:0, ip_id:rand() % 65536,
                     ip_off:0, ip_ttl:0x40, ip_p:IPPROTO_ICMP, ip_src:srcaddr,
                     data:lsrr, ip_len:38);
icmp = forge_icmp_packet(ip:ip, icmp_type:8, icmp_code:0, icmp_seq:0, icmp_id:rand() % 65536, data:d);
r = NULL;
for(i = 0; i < n && ! r; i++)
  r = send_packet(icmp, pcap_active:TRUE, pcap_filter:filter);

if(i < n) {
  set_kb_item(name:"Host/accept_lsrr", value:TRUE);
  security_message(port:0, protocol:"icmp");
}

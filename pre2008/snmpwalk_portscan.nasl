###############################################################################
# OpenVAS Vulnerability Test
#
# snmpwalk 'scanner'
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2004 Michel Arboi
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
  script_oid("1.3.6.1.4.1.25623.1.0.14274");
  script_version("2021-03-23T06:51:29+0000");
  script_tag(name:"last_modification", value:"2021-03-23 06:51:29 +0000 (Tue, 23 Mar 2021)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("snmpwalk 'scanner'");
  script_category(ACT_SCANNER);
  script_copyright("Copyright (C) 2004 Michel Arboi");
  script_family("Port scanners");
  script_dependencies("toolcheck.nasl", "host_alive_detection.nasl");
  script_mandatory_keys("Tools/Present/snmpwalk");

  script_add_preference(name:"Community name :", type:"entry", value:"public", id:1);
  script_add_preference(name:"SNMP protocol :", type:"radio", value:"1;2c", id:2);
  script_add_preference(name:"SNMP transport layer :", type:"radio", value:"udp;tcp", id:3);
  script_add_preference(name:"TCP/UDP port :", type:"entry", value:"", id:4);
  script_add_preference(name:"Number of retries :", type:"entry", value:"", id:5);
  script_add_preference(name:"Timeout between retries :", type:"entry", value:"", id:6);

  script_tag(name:"summary", value:"This plugin runs snmpwalk against the remote machine to find open ports.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

check = (!safe_checks()) || ("yes" >< get_preference("unscanned_closed"));

global_var  snmp_layer, argv, snmp_port, snmp_comm;
seen_tcp_ports = make_list(0); # Do not want to see this!
seen_udp_ports = make_list(0); # Do not want to see this!

function make_argv(obj, ip) {
  local_var i, p, ip;

  i = 0;
  argv = NULL;
  argv[i++] = "snmpwalk";

  p = script_get_preference("SNMP protocol :", id:2);
  if(!p)
    p = "2c";

  argv[i++] = "-v";
  argv[i++] = p;

  snmp_layer = "udp";

  if(!v506) {
    p = script_get_preference("SNMP transport layer :", id:3);
    if(p) {
      argv[i++] = "-T";
      argv[i++] = p;
      snmp_layer = p;
    }
  }

  p = script_get_preference("Number of retries :", id:5);
  if(p && p =~ "^[0-9]+$") {
    argv[i++] = "-r";
    argv[i++] = p;
  }

  p = script_get_preference("Timeout between retries :", id:6);
  if(p && p =~ "^[0-9]+$") {
    argv[i++] = "-t";
    argv[i++] = p;
  }

  p = script_get_preference("TCP/UDP port :", id:4);
  if(p && p =~ "^[0-9]+$") {
    argv[i++] = "-p";
    argv[i++] = p;
    snmp_port = p;
  }

  if(!v506)
    argv[i++] = ip;

  p = script_get_preference("Community name :", id:1);
  if(strlen(p) == 0)
    p = "public";

  if(v506)
    argv[i++] = "-c";

  argv[i++] = p;
  snmp_comm = p;
  # Version 5.0.6 or later: put the hostname *after* the options
  if(v506)
    argv[i++] = ip;

  argv[i++] = obj;
}

ver = pread(cmd:"snmpwalk", argv:make_list("snmpwalk", "-V"));
if(ereg(string:ver, pattern:"NET-SNMP version: +([6-9]\.|5\.([1-9]|0\.[6-9]))", icase:TRUE, multiline:TRUE))
  v506 = 1;
else
  v506 = 0;

ip = get_host_ip();

i = 0;
scanned = 0;
udp_scanned = 0;

foreach o(make_list("tcp.tcpConnTable.tcpConnEntry.tcpConnLocalPort.0.0.0.0",
                    "tcp.tcpConnTable.tcpConnEntry.tcpConnLocalPort." + ip,
                    "udp.udpTable.udpEntry.udpLocalPort.0.0.0.0",
                    "udp.udpTable.udpEntry.udpLocalPort." + ip)) {

  scanner_status(current:0, total:i++);
  make_argv(obj:o, ip:ip);
  buf = pread(cmd:"snmpwalk", argv:argv);
  proto = substr(o, 0, 2);
  if(buf) {
    foreach line(split(buf)) {
      v = eregmatch(pattern:'=[ \t]*([a-zA-Z0-9-]+:)?[ \t]*([0-9]+)[ \t\r\n]*$', string:line);
      if(!isnull(v)) {
        port = v[2];
        if(proto == "tcp" && !seen_tcp_ports[port]) {
          if(check && proto == "tcp") {
            soc = open_sock_tcp(port);
            if(soc) {
              scanner_add_port(proto: proto, port: port);
              close(soc);
            }
            # else
              #display("snmpwalk_portscan(", ip, "): TCP port ", port, " is closed in fact\n");
          }
          else
            scanner_add_port(proto: proto, port: port);
          seen_tcp_ports[port]++;
          scanned++;
        }
        if(proto == "udp" && !seen_udp_ports[port]) {
          scanner_add_port(proto:proto, port:port);
          seen_udp_ports[port]++;
          udp_scanned++;
        }
      }
    }
  }
}

if(scanned) {
  set_kb_item(name:"Host/scanned", value:TRUE);
  set_kb_item(name:"Host/full_scan", value:TRUE);
  set_kb_item(name:'Host/scanners/snmpwalk', value:TRUE);
  log_message(port:snmp_port, proto: snmp_layer, data:strcat("snmpwalk could get the open port list with the community name ", snmp_comm));
}

if(udp_scanned)
  set_kb_item(name:"Host/udp_scanned", value:TRUE);

exit(0);

# make_argv(obj:"host.hrSWInstalled.hrSWInstalledTable.hrSWInstalledEntry.hrSWInstalledName", ip:ip);

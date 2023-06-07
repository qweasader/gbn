# Copyright (C) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103835");
  script_version("2022-07-08T10:11:49+0000");
  script_tag(name:"last_modification", value:"2022-07-08 10:11:49 +0000 (Fri, 08 Jul 2022)");
  script_tag(name:"creation_date", value:"2013-11-26 11:39:47 +0100 (Tue, 26 Nov 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Intelligent Platform Management Interface (IPMI) Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_require_udp_ports(623);

  script_tag(name:"summary", value:"Detection of services supporting the Intelligent Platform
  Management Interface (IPMI).");

  script_tag(name:"insight", value:"The IPMI is a standardized computer system interface used by
  system administrators for out-of-band management of computer systems and monitoring of their
  operation.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("byte_func.inc");
include("port_service_func.inc");

port = 623;
if(!get_udp_port_state(port))
  exit(0);

rmcp = raw_string(0x06, 0x00, 0xff, 0x07); # Remote Management Control Protocol
gcac = raw_string(0x38);                   # Get Channel Authentication Capabilities

header = rmcp + raw_string(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x09, 0x20, 0x18, 0xc8, 0x81, 0x00) + gcac;

level = raw_string(0x04); # Administrator

ipmi_20 = header + raw_string(0x8e) + level + raw_string(0xb5);
ipmi_15 = header + raw_string(0x0e) + level + raw_string(0x35);

reqs = make_list(ipmi_20, ipmi_15);

foreach req(reqs) {

  if(!soc = open_sock_udp(port))
    continue;

  send(socket:soc, data:req);
  recv = recv(socket:soc, length:128);
  close(soc);

  if(!recv || hexstr(recv) !~ "0600ff07" || strlen(recv) < 24 || ord(recv[20]) != 0)
    continue;

  auth_support = dec2bin(dec:ord(recv[22]));

  if(auth_support) {

    if(auth_support[7] == 1) {
      set_kb_item(name:"ipmi/no_auth_supported", value:TRUE);
      set_kb_item(name:"ipmi/" + port + "/no_auth_supported", value:TRUE);
    }

    if(auth_support[6] == 1) {
      set_kb_item(name:"ipmi/md2_supported", value:TRUE);
      set_kb_item(name:"ipmi/" + port + "/md2_supported", value:TRUE);
    }
  }

  ipmi_version = dec2bin(dec:ord(recv[24]));
  ipmi_vers_str = "v1.5";

  if(ipmi_version) {
    if(ipmi_version[6] == 1) {
      set_kb_item(name:"ipmi/version/2.0", value:TRUE);
      set_kb_item(name:"ipmi/" + port + "/version/2.0", value:TRUE);
      ipmi_vers_str += " v2.0";
    }
  }

  non_null = dec2bin(dec:ord(recv[23]));

  if(non_null) {

    if(non_null[7] == 1) {
      set_kb_item(name:"ipmi/anonymous_login", value:TRUE);
      set_kb_item(name:"ipmi/" + port + "/anonymous_login", value:TRUE);
    }

    if(non_null[6] == 1) {
      set_kb_item(name:"ipmi/null_username", value:TRUE);
      set_kb_item(name:"ipmi/" + port + "/null_username", value:TRUE);
    }
  }

  service_register(port:port, ipproto:"udp", proto:"ipmi", message:"An IPMI service is running at this port. Supported IPMI version(s): " + ipmi_vers_str);
  log_message(data:"An IPMI service is running at this port. Supported IPMI version(s): " + ipmi_vers_str, port:port, proto:"udp");

  exit(0);

}

exit(0);

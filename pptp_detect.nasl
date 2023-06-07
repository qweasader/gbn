###############################################################################
# OpenVAS Vulnerability Test
#
# PPTP detection and versioning
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 2005 SecuriTeam
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
  script_oid("1.3.6.1.4.1.25623.1.0.10622");
  script_version("2021-06-11T09:28:25+0000");
  script_tag(name:"last_modification", value:"2021-06-11 09:28:25 +0000 (Fri, 11 Jun 2021)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("PPTP Service Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 SecuriTeam");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports(1723);

  script_xref(name:"URL", value:"http://www.counterpane.com/pptp-faq.html");

  script_tag(name:"solution", value:"Restrict access to this port from untrusted networks. Make sure
  only encrypted channels are allowed through the PPTP (VPN) connection.");

  script_tag(name:"summary", value:"The remote host seems to be running a PPTP (VPN) service, this service
  allows remote users to connect to the internal network and play a trusted rule in it. This service should
  be protect with encrypted username & password combinations, and should be accessible only to trusted
  individuals. By default the service leaks out such information as Server version (PPTP version), Hostname
  and Vendor string this could help an attacker better prepare her next attack.

  Also note that PPTP is not configured as being cryptographically
  secure, and you should use another VPN method if you can.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");

port = 1723;
if(!get_port_state(port))
  exit(0);

if(!soc = open_sock_tcp(port))
  exit(0);

buffer =
raw_string(0x00, 0x9C) +
# Length

raw_string(0x00, 0x01) +
# Control packet

raw_string(0x1A, 0x2B, 0x3C, 0x4D) +
# Magic Cookie

raw_string(0x00, 0x01) +
# Control Message = Start Session Request

raw_string(0x00, 0x00) +
# Reserved word 1

raw_string(0x01, 0x00) +
# Protocol version = 256

raw_string(0x00) +
# Reserved byte 1

raw_string(0x00) +
# Reserved byte 2

raw_string(0x00, 0x00, 0x00, 0x01) +
# Framing Capability Summary (Can do async PPP)

raw_string(0x00, 0x00, 0x00, 0x01) +
# Bearer Capability Summary (Can do analog calls)

raw_string(0x00, 0x00) +
# Max Channels

raw_string(0x08, 0x70) +
# Firmware Revision = 2160

raw_string(
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00) +
# Hostname

raw_string(
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00);
# Vendor string

send(socket:soc, data:buffer);
rec_buffer = recv(socket:soc, length:156);
close(soc);

if(strlen(rec_buffer) < 156)
  exit(0);

if((ord(rec_buffer[2]) == 0) && (ord(rec_buffer[3]) == 1)) { # Control Packet
  if((ord(rec_buffer[8]) == 0) && (ord(rec_buffer[9]) == 2)) { # Replay Packet

    firmware_version = 0;
    firmware_version = ord(rec_buffer[26]) * 256 + ord(rec_buffer[27]);

    host_name = "";
    for(i=28; (i<28+64) && (ord(rec_buffer[i]) > 0); i++)
      host_name += rec_buffer[i];

    if(strlen(host_name) > 0) {
      set_kb_item(name:"pptp/hostname/detected", value:TRUE);
      set_kb_item(name:"pptp/" + port + "/hostname", value:host_name);
    } else {
      host_name = "N/A";
    }

    vendor_string = "";
    for(i=92; (i<92+64) && (ord(rec_buffer[i]) > 0); i++)
      vendor_string += rec_buffer[i];

    if(strlen(vendor_string) > 0) {
      set_kb_item(name:"pptp/vendor_string/detected", value:TRUE);
      set_kb_item(name:"pptp/" + port + "/vendor_string", value:vendor_string);
    } else {
      vendor_string = "N/A";
    }

    report = string("A PPTP service is running on this port.\n\n",
                    "Firmware Revision: ", firmware_version, "\n",
                    "Hostname:          ", host_name, "\n",
                    "Vendor String:     ", vendor_string);
    log_message(port:port, data:report);
    service_register(port:port, proto:"pptp");
  }
}

exit(0);

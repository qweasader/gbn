###############################################################################
# OpenVAS Vulnerability Test
#
# POP2 Unencrypted Cleartext Login
#
# Authors:
# George A. Theall, <theall@tifaware.com>
#
# Copyright:
# Copyright (C) 2005 George A. Theall
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
  script_oid("1.3.6.1.4.1.25623.1.0.15854");
  script_version("2022-06-03T06:21:25+0000");
  script_tag(name:"last_modification", value:"2022-06-03 06:21:25 +0000 (Fri, 03 Jun 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:N");
  script_xref(name:"OSVDB", value:"3119");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("POP2 Unencrypted Cleartext Login");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 George A. Theall");
  script_family("General");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/pop2", 109);

  script_tag(name:"summary", value:"The remote host is running a POP2 daemon that allows cleartext logins over
  unencrypted connections.");

  script_tag(name:"impact", value:"An attacker can uncover login names and
  passwords by sniffing traffic to the POP2 daemon.");

  script_tag(name:"solution", value:"Encrypt traffic with SSL/TLS using stunnel.");

  exit(0);
}

include("port_service_func.inc");

port = service_get_port(default:109, proto:"pop2");

if(!get_port_state(port))

# nb: skip it if traffic is encrypted.
encaps = get_port_transport(port);
if (encaps > ENCAPS_IP)
  exit(0);

soc = open_sock_tcp(port);
if (!soc)
  exit(0);

r = recv_line(socket:soc, length:4096);
close(soc);

if (!r || "POP" >!< r)
  exit(0);

# nb: POP2 doesn't support encrypted logins so there's no need to
#     actually try to log in. [Heck, I probably don't even need to
#     establish a connection.]
security_message(port:port);
exit(0);

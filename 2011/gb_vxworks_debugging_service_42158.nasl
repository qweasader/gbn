# Copyright (C) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103367");
  script_cve_id("CVE-2010-2965");
  script_version("2022-12-07T10:11:17+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-12-07 10:11:17 +0000 (Wed, 07 Dec 2022)");
  script_tag(name:"creation_date", value:"2011-12-14 16:57:31 +0100 (Wed, 14 Dec 2011)");
  script_name("VxWorks Debugging Service Security-Bypass Vulnerability");
  script_category(ACT_ATTACK);
  script_family("General");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_require_udp_ports(17185);

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42158");
  script_xref(name:"URL", value:"http://blog.metasploit.com/2010/08/vxworks-vulnerabilities.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/512825");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/362332");

  script_tag(name:"summary", value:"VxWorks is prone to a remote security-bypass vulnerability.");

  script_tag(name:"impact", value:"Successful exploits will allow remote attackers to perform
  debugging tasks on the vulnerable device.");

  script_tag(name:"affected", value:"The issue affects multiple products from multiple vendors that ship
  with the VxWorks operating system.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by
  another one.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

port = 17185;
if(!get_udp_port_state(port))
  exit(0);

if(!soc = open_sock_udp(port))
  exit(0);

function get_value(data, blob) {

  local_var data, blob;
  local_var tmp, i, value;

  tmp = substr(data, blob);
  for(i = 0; i < strlen(data); i++) {
    if(tmp[i] == '\0') {
      return value;
    } else {
      value += tmp[i];
    }
  }
  return value;
}

packet = raw_string(0x50,0x26,0x30,0x91,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x55,0x55,0x55,0x55,
                    0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x2c,
                    0x8b,0x12,0x00,0x01);

send(socket:soc, data:packet);
recv = recv(socket:soc, length:4096);
if(!recv || strlen(recv) < 8 || ord(recv[7]) != 1)
  exit(0);

agent_vers = get_value(data:recv, blob:40);
if(!isnull(agent_vers)) {
  report += string("Agent version: ", agent_vers, "\n");
}

rtv = get_value(data:recv, blob:60);
if(!isnull(rtv)) {
  report += string("Run time version: ", rtv, "\n");
}

bname = get_value(data:recv, blob:88);
if(!isnull(bname)) {
  report += string("Board name: ", bname, "\n");
}

if(report) {
  report = string("It was possible to gather the following information from the remote host:\n\n") + report;
  security_message(port:port, data:report, proto:"udp");
} else {
  security_message(port:port, proto:"udp");
}

exit(0);
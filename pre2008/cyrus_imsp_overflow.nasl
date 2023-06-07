# OpenVAS Vulnerability Test
# Description: cyrus-imsp abook_dbname buffer overflow
#
# Authors:
# Noam Rathaus <noam@beyondsecurity.com>
# Changes by rd :
# - description
# - minor bugfixes
#
# Copyright:
# Copyright (C) 2003 Noam Rathaus
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11953");
  script_version("2022-12-26T10:12:01+0000");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9227");
  script_tag(name:"last_modification", value:"2022-12-26 10:12:01 +0000 (Mon, 26 Dec 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("cyrus-imsp abook_dbname Buffer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2003 Noam Rathaus");
  script_family("Gain a shell remotely");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/imsp", 406);

  script_tag(name:"summary", value:"The cyrus-imsp (Internet Message Support Protocol) daemon is
  prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The overflow occurs when the user issues a too long argument as
  his name, causing an overflow in the abook_dbname function command.");

  script_tag(name:"impact", value:"An attacker could exploit this bug to execute arbitrary code on
  this system with the privileges of the root user.");

  script_tag(name:"solution", value:"Update to version 1.6a4, 1.7a or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("misc_func.inc");
include("port_service_func.inc");

port = service_get_port(default:406, proto:"imsp");
soc = open_sock_tcp(port);
if(!soc)
  exit(0);

banner = recv_line(socket:soc, length:4096);
close(soc);

if( banner && ereg(pattern:".* Cyrus IMSP version (0\..*|1\.[0-5]|1\.6|1\.6a[0-3]|1\.7) ready", string:banner) ) {
  security_message(port:port);
  exit(0);
}

exit(99);

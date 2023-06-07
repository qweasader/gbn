# OpenVAS Vulnerability Test
# Description: INN buffer overflow
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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
  script_oid("1.3.6.1.4.1.25623.1.0.14683");
  script_version("2022-05-12T09:32:01+0000");
  script_tag(name:"last_modification", value:"2022-05-12 09:32:01 +0000 (Thu, 12 May 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/1249");
  script_xref(name:"OSVDB", value:"1353");
  script_cve_id("CVE-2000-0360");
  script_name("INN buffer overflow");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Buffer overflow");
  script_dependencies("nntpserver_detect.nasl");
  script_require_ports("Services/nntp", 119);
  script_mandatory_keys("nntp/detected");

  script_tag(name:"solution", value:"Upgrade to version 2.2.2 or later.");

  script_tag(name:"summary", value:"The remote version of this INN (InterNetNews) server
  does not do proper bounds checking.");

  script_tag(name:"impact", value:"An attacker may exploit this issue to crash the remote
  service by overflowing some of the buffers by sending a maliciously formatted news article.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("nntp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = nntp_get_port(default:119);
banner = get_kb_item("nntp/banner/" + port);
if(!banner || "INN" >!< banner)
  exit(0);

if(egrep(string:banner, pattern:"^20[0-9] .* INN 2\.(([01]\..*)|(2\.[01][^0-9])) .*$")) {
  security_message(port:port);
  exit(0);
}

exit(99);

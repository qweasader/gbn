# OpenVAS Vulnerability Test
# Description: IgnitionServer Irc operator privilege escalation vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.14388");
  script_version("2022-05-12T09:32:01+0000");
  script_tag(name:"last_modification", value:"2022-05-12 09:32:01 +0000 (Thu, 12 May 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-2553");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9783");
  script_xref(name:"OSVDB", value:"4121");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_name("IgnitionServer IIRC Operator Privilege Escalation Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Privilege escalation");
  script_dependencies("ircd.nasl");
  script_require_ports("Services/irc", 6667);
  script_mandatory_keys("ircd/banner");

  script_tag(name:"solution", value:"Update to version 0.2.1-BRC1 or later.");

  script_tag(name:"summary", value:"IgnitionServer IRC service may be vulnerable to a flaw that let
  an remote attacker to gain elevated privileges on the system.");

  script_tag(name:"impact", value:"A remote attacker, who is an operator, can supply an unofficial
  command to the server to obtain elevated privileges and become a global IRC operator.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("misc_func.inc");
include("port_service_func.inc");

port = service_get_port(default:6667, proto:"irc");

banner = get_kb_item("irc/banner/" + port);
if(!banner || "ignitionServer" >!< banner)
  exit(0);

if(egrep(pattern:".*ignitionServer 0\.([01]\.|2\.0).*", string:banner)) {
  security_message(port:port);
  exit(0);
}

exit(99);

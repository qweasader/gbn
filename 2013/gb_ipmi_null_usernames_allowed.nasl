# Copyright (C) 2013 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103838");
  script_version("2022-07-08T10:11:49+0000");
  script_tag(name:"last_modification", value:"2022-07-08 10:11:49 +0000 (Fri, 08 Jul 2022)");
  script_tag(name:"creation_date", value:"2013-11-26 12:23:03 +0100 (Tue, 26 Nov 2013)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("IPMI Null Usernames Allowed");

  script_category(ACT_GATHER_INFO);

  script_family("General");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_ipmi_detect.nasl");
  script_require_udp_ports("Services/udp/ipmi", 623);
  script_mandatory_keys("ipmi/null_username");

  script_tag(name:"summary", value:"The remote IPMI service allows 'null usernames'.");

  script_tag(name:"solution", value:"Don't allow accounts with a null username or password.");

  exit(0);
}

include("port_service_func.inc");

port = service_get_port(default:623, ipproto:"udp", proto:"ipmi");

if (get_kb_item("ipmi/" + port + "/null_username")) {
  security_message(port:port, proto:"udp");
  exit(0);
}

exit(99);

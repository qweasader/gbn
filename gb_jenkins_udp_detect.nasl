# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.142666");
  script_version("2021-05-25T11:10:13+0000");
  script_tag(name:"last_modification", value:"2021-05-25 11:10:13 +0000 (Tue, 25 May 2021)");
  script_tag(name:"creation_date", value:"2019-07-24 08:20:18 +0000 (Wed, 24 Jul 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Jenkins Detection (Auto Discovery)");

  script_tag(name:"summary", value:"Auto Discovery service based detection of the Jenkins automation
  server.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_open_udp_ports.nasl");
  script_require_udp_ports("Services/udp/unknown", 33848);

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = unknownservice_get_port(default: 33848, ipproto: "udp");

if (!soc = open_sock_udp(port))
  exit(0);

send(socket: soc, data: "\n");
recv = recv(socket: soc, length: 512);
close(soc);

if (!recv || "<hudson><" >!< recv || "<server-id>" >!< recv)
  exit(0);

version = "unknown";

set_kb_item(name: "jenkins/detected", value: TRUE);
set_kb_item(name: "jenkins/autodiscovery/detected", value: TRUE);
set_kb_item(name: "jenkins/autodiscovery/port", value: port);

# <hudson><version>2.164.3</version><url>http://localhost:8080/</url><server-id>ddfd1cfda3969f8fecbd0079ab5dd8aa</server-id></hudson>
vers = eregmatch(pattern: "<version>([0-9.]+)</version>", string: recv);
if (!isnull(vers[1])) {
  version = vers[1];
  if (version =~ "^[0-9]+\.[0-9]+\.[0-9]+")
    set_kb_item(name: "jenkins/" + port + "/is_lts", value: TRUE);
}

set_kb_item(name: "jenkins/autodiscovery/" + port + "/version", value: version);
set_kb_item(name: "jenkins/autodiscovery/" + port + "/concluded", value: recv);

exit(0);
# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.143257");
  script_version("2020-08-24T08:40:10+0000");
  script_tag(name:"last_modification", value:"2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-12-16 09:23:54 +0000 (Mon, 16 Dec 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Inim SmartLAN Detection (Telnet)");

  script_tag(name:"summary", value:"Detection of Inim SmartLAN devices.

  This script performs Telnet based detection of Inim SmartLAN devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/inim/smartlan/detected");

  exit(0);
}

include("dump.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("telnet_func.inc");

port = telnet_get_port(default: 23);

if (!banner = telnet_get_banner(port: port))
  exit(0);

if ("SmartLAN login:" >< banner) {
  set_kb_item(name: "inim/smartlan/detected", value: TRUE);
  set_kb_item(name: "inim/smartlan/telnet/detected", value: TRUE);
  set_kb_item(name: "inim/smartlan/telnet/port", value: port);
  set_kb_item(name: "inim/smartlan/telnet/" + port + "/concluded", value: banner);
}

exit(0);

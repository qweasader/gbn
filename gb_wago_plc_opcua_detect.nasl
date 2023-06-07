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
  script_oid("1.3.6.1.4.1.25623.1.0.142065");
  script_version("2020-11-10T15:30:28+0000");
  script_tag(name:"last_modification", value:"2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)");
  script_tag(name:"creation_date", value:"2019-03-04 12:13:39 +0700 (Mon, 04 Mar 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("WAGO PLC Detection (OPC-UA)");

  script_tag(name:"summary", value:"OPC-UA based detection of WAGO PLC Controllers.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_opc_ua_detect.nasl");
  script_mandatory_keys("opcua/detected");

  exit(0);
}

include("port_service_func.inc");

prod_name = get_kb_item("opcua/product_name");
if (!prod_name || prod_name !~ "^WAGO ")
  exit(0);

port = service_get_port(default: 4840, proto: "opc-ua");

set_kb_item(name: 'wago_plc/detected', value: TRUE);
set_kb_item(name: "wago_plc/opcua/detected", value: TRUE);
set_kb_item(name: 'wago_plc/opcua/port', value: port);

mod = eregmatch(pattern: "WAGO (.*)", string: prod_name);
if (!isnull(mod[1]))
  set_kb_item(name: 'wago_plc/opcua/' + port + '/model', value: mod[1]);

if (version = get_kb_item("opcua/version"))
  set_kb_item(name: 'wago_plc/opcua/' + port + '/opc_version', value: version);

if (build = get_kb_item("opcua/build"))
  set_kb_item(name: 'wago_plc/opcua/' + port + '/build', value: build);

exit(0);

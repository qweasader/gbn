###############################################################################
# OpenVAS Vulnerability Test
#
# WAGO PLC Detection (EtherNet/IP)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141768");
  script_version("2020-11-10T15:30:28+0000");
  script_tag(name:"last_modification", value:"2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)");
  script_tag(name:"creation_date", value:"2018-12-07 13:39:37 +0700 (Fri, 07 Dec 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("WAGO PLC Detection (EtherNet/IP)");

  script_tag(name:"summary", value:"This script performs EtherNet/IP based detection of WAGO PLC Controllers.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_ethernetip_tcp_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_ethernetip_udp_detect.nasl");
  script_mandatory_keys("ethernetip/detected");

  exit(0);
}

include("port_service_func.inc");

if (!proto = get_kb_item("ethernetip/proto"))
  exit(0);

port = service_get_port(default: 44818, proto: "ethernetip", ipproto: proto);

prod_name = get_kb_item("ethernetip/" + port + "/" + proto + "/product_name");
# e.g.
# WAGO 750-881 PFC ETHERNET
# WAGO 750-880 PFC Telecontr. ECO
# WAGO 750-880 PFC ETHERNET
#
# nb: There are also a few like e.g. the following available:
# WAGO Ethernet(10/100MBit)-FBC
# which are no PLCs.
if (!prod_name || prod_name !~ "^WAGO 750-")
  exit(0);

set_kb_item(name: "wago_plc/detected", value: TRUE);
set_kb_item(name: "wago_plc/ethernetip/detected", value: TRUE);
set_kb_item(name: "wago_plc/ethernetip/port", value: port);
set_kb_item(name: "wago_plc/ethernetip/proto", value: proto);
set_kb_item(name: "wago_plc/ethernetip/" + port + "/proto", value: proto);

mod = eregmatch(pattern: "WAGO (.*)", string: prod_name);
if (!isnull(mod[1]))
  set_kb_item(name: "wago_plc/ethernetip/" + port + "/" + proto + "/model", value: mod[1]);

if (rev = get_kb_item("ethernetip/" + port + "/" + proto + "/revision"))
  set_kb_item(name: "wago_plc/ethernetip/" + port + "/" + proto + "/fw_version", value: rev);

exit(0);

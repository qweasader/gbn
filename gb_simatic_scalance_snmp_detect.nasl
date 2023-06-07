# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.140748");
  script_version("2021-04-28T11:39:57+0000");
  script_tag(name:"last_modification", value:"2021-04-28 11:39:57 +0000 (Wed, 28 Apr 2021)");
  script_tag(name:"creation_date", value:"2018-02-05 15:43:30 +0700 (Mon, 05 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Siemens SIMATIC SCALANCE Device Detection (SNMP)");

  script_tag(name:"summary", value:"SNMP based detection of Siemens SIMATIC SCALANCE devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_snmp_sysdescr_detect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("snmp_func.inc");

port = snmp_get_port(default: 161);

sysdesc = snmp_get_sysdescr(port: port);
if (!sysdesc)
  exit(0);

# Siemens, SIMATIC NET, SCALANCE M876-4 EU, 6GK5 876-4AA00-2BA2, HW: Version 1, FW: Version V04.02.03, SVPJ5127948
# Siemens, SIMATIC NET, Scalance S612, 6GK56120BA102AA3, HW: Version 2, FW: Version V03.00.00.01_01.00.00.01, VPCO544487
if (egrep(string: sysdesc, pattern: "Siemens, SIMATIC NET, SCALANCE", icase: TRUE)) {
  model = "unknown";
  fw_version = "unknown";
  hw_version = "unknown";
  module = "unknown";

  set_kb_item(name: "siemens/simatic/scalance/detected", value: TRUE);
  set_kb_item(name: "siemens/simatic/scalance/snmp/port", value: port);
  set_kb_item(name: "siemens/simatic/scalance/snmp/" + port + "/concluded", value: sysdesc);

  sp = split(sysdesc, sep: ",", keep: FALSE);

  # Model
  if (!isnull(sp[2])) {
    mo = eregmatch(pattern: "scalance (.*)", string: sp[2], icase: TRUE);
    if (!isnull(mo[1]))
      model = mo[1];
  }

  # Version
  if (!isnull(sp[5])) {
    vers = eregmatch(pattern: "V([0-9.]+)", string: sp[5]);
    if (!isnull(vers[1]))
      fw_version = vers[1];
  }

  # Module
  if (!isnull(sp[3])) {
    modu = eregmatch(pattern: "^ (.*)", string: sp[3]);
    if (!isnull(modu[1]))
      module = modu[1];
  }

  # HW Version
  if (!isnull(sp[4])) {
    hw = eregmatch(pattern: "HW: Version ([0-9]+)", string: sp[4]);
    if (!isnull(hw[1]))
      hw_version = hw[1];
  }

  set_kb_item(name: "siemens/simatic/scalance/snmp/" + port + "/model", value: model);
  set_kb_item(name: "siemens/simatic/scalance/snmp/" + port + "/fw_version", value: fw_version);
  set_kb_item(name: "siemens/simatic/scalance/snmp/" + port + "/hw_version", value: hw_version);
  set_kb_item(name: "siemens/simatic/scalance/snmp/" + port + "/module", value: module);
}

exit(0);


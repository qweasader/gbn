###############################################################################
# OpenVAS Vulnerability Test
#
# Huawei Versatile Security Platform (VSP) Detection (SNMP)
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141199");
  script_version("2021-03-24T10:08:26+0000");
  script_tag(name:"last_modification", value:"2021-03-24 10:08:26 +0000 (Wed, 24 Mar 2021)");
  script_tag(name:"creation_date", value:"2018-06-19 16:42:10 +0700 (Tue, 19 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Huawei Versatile Security Platform (VSP) Detection (SNMP)");

  script_tag(name:"summary", value:"SNMP based detection of Huawei Versatile Security Platform (VSP).");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_snmp_sysdescr_detect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  script_xref(name:"URL", value:"https://e.huawei.com/en/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("snmp_func.inc");

port = snmp_get_port(default: 161);
sysdesc = snmp_get_sysdescr(port: port);
if (!sysdesc)
  exit(0);

# Huawei Storage & Network Security Versatile Security Platform Software
# Software Version: VSP (R) Software, Version 3.30 USG5300 V100R003C01SPC600
#
# Huawei Versatile Security Platform
# Software Version: VRP (R) software, Version 5.30 USG5160 V300R001C00SPC700
if (sysdesc =~ "Huawei (Storage & Network Security |Symantec )?Versatile Security Platform") {

  version = "unknown";
  model = "Unknown Model";
  coe_model = "vsp_unknown_model";

  mo = eregmatch(pattern: "Version [0-9.]+ ([^ ]+)", string: sysdesc);
  if (!isnull(mo[1])) {
    model = mo[1];
    cpe_model = tolower(model);
    vers = eregmatch(pattern: model + " (V[0-9A-Z]+)", string: sysdesc);
    if (!isnull(vers[1])) {
      version = vers[1];
      set_kb_item(name: "huawei_vsp/version", value: version);
    }
  }

  set_kb_item(name: "huawei_vsp/detected", value: TRUE);
  set_kb_item(name: "huawei_vsp/model", value: model);
  set_kb_item(name: "huawei/data_communication_product/detected", value: TRUE);

  cpe = build_cpe(value: tolower(version), exp: "^(v[0-9a-z]+)", base: "cpe:/h:huawei:" + cpe_model + ":");
  if (!cpe)
    cpe = "cpe:/h:huawei:" + cpe_model;

  register_product(cpe: cpe, location: port + "/udp", port: port, service: "snmp", proto: "udp");

  log_message(data: build_detection_report(app: "Huawei Versatile Security Platform " + model, version: version,
                                           install: port + "/udp", cpe: cpe, concluded: sysdesc),
              port: port, proto: "udp");
  exit(0);
}

exit(0);

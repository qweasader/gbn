# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105382");
  script_version("2023-08-10T05:05:53+0000");
  script_tag(name:"last_modification", value:"2023-08-10 05:05:53 +0000 (Thu, 10 Aug 2023)");
  script_tag(name:"creation_date", value:"2015-09-22 14:49:34 +0200 (Tue, 22 Sep 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cisco Wireless LAN Controller (WLC) Detection (SNMP)");

  script_tag(name:"summary", value:"SNMP based detection of Cisco Wireless LAN Controller (WLC).");

  script_category(ACT_GATHER_INFO);

  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  exit(0);
}

include("snmp_func.inc");

port    = snmp_get_port(default:161);
sysdesc = snmp_get_sysdescr(port:port);
if (!sysdesc || "Cisco Controller" >!< sysdesc)
  exit(0);

set_kb_item(name: "cisco/wlc/detected", value: TRUE);
set_kb_item(name: "cisco/wlc/snmp/detected", value: TRUE);
set_kb_item(name: "cisco/wlc/snmp/port", value: port);
set_kb_item(name: "cisco/wlc/snmp/" + port + "/concluded", value: sysdesc);

version = "unknown";
model = "unknown";

sw_oid = "1.3.6.1.2.1.47.1.1.1.1.10.1";
vers = snmp_get(port: port, oid: sw_oid);
if (!isnull(vers)) {
  version = str_replace(string: vers, find: '"', replace: "");
  set_kb_item(name: "cisco/wlc/snmp/" + port + "/concludedVers", value: vers);
  set_kb_item(name: "cisco/wlc/snmp/" + port + "/concludedVersOID", value: sw_oid);
}

mod_oid = "1.3.6.1.2.1.47.1.1.1.1.13.1";
mod = snmp_get(port: port, oid: mod_oid);
if (!isnull(mod)) {
  model = str_replace(string: mod, find: '"', replace: "");
  set_kb_item(name: "cisco/wlc/snmp/" + port + "/concludedMod", value: mod);
  set_kb_item(name: "cisco/wlc/snmp/" + port + "/concludedModOID", value: mod_oid);
}

set_kb_item(name: "cisco/wlc/snmp/" + port + "/model", value: model);
set_kb_item(name: "cisco/wlc/snmp/" + port + "/version", value: version);

exit(0);
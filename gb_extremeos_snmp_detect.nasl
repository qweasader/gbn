# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106413");
  script_version("2023-08-10T05:05:53+0000");
  script_tag(name:"last_modification", value:"2023-08-10 05:05:53 +0000 (Thu, 10 Aug 2023)");
  script_tag(name:"creation_date", value:"2016-11-25 11:50:20 +0700 (Fri, 25 Nov 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Extreme ExtremeXOS Detection (SNMP)");

  script_tag(name:"summary", value:"This script performs SNMP based detection of Extreme ExtremeXOS.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");
include("snmp_func.inc");

port    = snmp_get_port(default:161);
sysdesc = snmp_get_sysdescr(port:port);
if(!sysdesc) exit(0);

if ("ExtremeXOS" >< sysdesc) {
  version = "unknown";
  patch = "None";

  mod = eregmatch(pattern: "ExtremeXOS \(([a-zA-Z0-9-]+)", string: sysdesc);
  if (isnull(mod[1]))
    exit(0);

  model = mod[1];
  set_kb_item(name: "extremexos/model", value: model);
  set_kb_item(name: "extremexos/detected", value: TRUE);

  vers = eregmatch(pattern: "ExtremeXOS .* version ([0-9.]+)", string: sysdesc);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "extremexos/version", value: version);
  }

  p = eregmatch(pattern: "-patch([0-9-]+)", string: sysdesc);
  if (!isnull(p[1])) {
    patch = p[1];
    set_kb_item(name: "extremexos/patch", value: str_replace(string: patch, find: "-", replace: "."));
  }

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:extreme:extremexos:");
  if (!cpe)
    cpe = 'cpe:/a:extreme:extremexos';

  os_cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/o:extremenetworks:exos:");
  if (!os_cpe)
    os_cpe = 'cpe:/o:extremenetworks:exos';

  register_product(cpe: cpe, port: port, proto: "udp", location: port + "/udp", service: "snmp" );
  os_register_and_report(os: "Extreme Networks ExtremeXOS", cpe: os_cpe, banner_type: "SNMP sysdesc", banner: sysdesc, port: port, proto: "udp", desc: "Extreme ExtremeXOS Detection (SNMP)", runs_key: "unixoide");

  log_message(data: build_detection_report(app: "Extreme ExtremeXOS " + model, version: version, cpe: cpe,
                                           install: port + "/udp", concluded: sysdesc, extra: "Patch: " + patch),
              port: port, proto: 'udp');
  exit(0);
}

exit(0);

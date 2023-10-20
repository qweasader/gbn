# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142905");
  script_version("2023-08-10T05:05:53+0000");
  script_tag(name:"last_modification", value:"2023-08-10 05:05:53 +0000 (Thu, 10 Aug 2023)");
  script_tag(name:"creation_date", value:"2019-09-18 02:50:20 +0000 (Wed, 18 Sep 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Toshiba Printer Detection (SNMP)");

  script_tag(name:"summary", value:"This script performs SNMP based detection of Toshiba printer devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  exit(0);
}

include("snmp_func.inc");

port = snmp_get_port(default: 161);

sysdesc = snmp_get_sysdescr(port: port);
if (!sysdesc)
  exit(0);

# TOSHIBA e-STUDIO3555C
# TOSHIBA e-STUDIO7506AC
if (sysdesc =~ "^TOSHIBA e-STUDIO") {
  set_kb_item(name: 'toshiba_printer/detected', value: TRUE);
  set_kb_item(name: 'toshiba_printer/snmp/detected', value: TRUE);
  set_kb_item(name: 'toshiba_printer/snmp/port', value: port);
  set_kb_item(name: 'toshiba_printer/snmp/' + port + '/concluded', value: sysdesc );

  model = eregmatch(pattern: "TOSHIBA ([^ ]+)", string: sysdesc);
  if (!isnull(model[1]))
    set_kb_item(name: 'toshiba_printer/snmp/' + port + '/model', value: model[1]);
}

exit(0);

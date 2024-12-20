# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105079");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-08-10T05:05:53+0000");
  script_tag(name:"last_modification", value:"2023-08-10 05:05:53 +0000 (Thu, 10 Aug 2023)");
  script_tag(name:"creation_date", value:"2014-09-04 09:48:32 +0200 (Thu, 04 Sep 2014)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cisco IOS XR Detection (SNMP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  script_tag(name:"summary", value:"SNMP based detection of Cisco IOS XR.");

  exit(0);
}

include("host_details.inc");
include("snmp_func.inc");

port = snmp_get_port(default: 161);

sysdesc = snmp_get_sysdescr(port: port);
if (!sysdesc)
  exit(0);

# Cisco IOS XR Software (Cisco 12816/PRP), Version 4.3.2[Default] Copyright (c) 2014 by Cisco Systems, Inc.
# Cisco IOS XR Software (Cisco ASR9K Series), Version 5.1.1[Default]  Copyright (c) 2014 by Cisco Systems, Inc.
# Cisco IOS XR Software (Cisco 12404/PRP), Version 3.6.0[00] Copyright (c) 2007 by Cisco Systems, Inc.
# Cisco IOS XR Software (IOS-XRv 9000), Version 7.3.2
# Cisco IOS XR Software (NCS-560), Version 7.3.2 Copyright (c) 2013-2021 by Cisco Systems, Inc.
if ("Cisco IOS XR" >!< sysdesc)
  exit(0);

model = "unknown";
version = "unknown";

set_kb_item(name:"cisco/ios_xr/detected", value: TRUE);
set_kb_item(name:"cisco/ios_xr/snmp/detected", value: TRUE);
set_kb_item(name:"cisco/ios_xr/snmp/port", value: port);
set_kb_item(name:"cisco/ios_xr/snmp/" + port + "/concluded", value: sysdesc);

vers = eregmatch(pattern: "Cisco IOS XR Software.*Version ([0-9.]+)", string: sysdesc);
if (!isnull(vers[1]))
  version = vers[1];

mod = eregmatch(pattern: "Cisco IOS XR Software \((Cisco |IOS-XRv )?([^)]+)\)", string: sysdesc);
if (!isnull(mod[2])) {
  if (mod[1] !~ "^IOS-XRv")
    model = mod[2];
  else
    model = mod[1] + mod[2];
}

set_kb_item(name: "cisco/ios_xr/snmp/" + port + "/model", value: model);
set_kb_item(name: "cisco/ios_xr/snmp/" + port + "/version", value: version);

exit(0);

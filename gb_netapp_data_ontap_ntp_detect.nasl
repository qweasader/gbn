# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140347");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-09-04 15:55:36 +0700 (Mon, 04 Sep 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("NetApp Data ONTAP Detection (NTP)");

  script_tag(name:"summary", value:"Detection of NetApp Data ONTAP.

This script performs NTP based detection of NetApp Data ONTAP devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("ntp_open.nasl");
  script_require_udp_ports("Services/udp/ntp", 123);
  script_mandatory_keys("ntp/system_banner/available");

  exit(0);
}

include("misc_func.inc");
include("port_service_func.inc");

port = service_get_port(default: 123, ipproto: "udp", proto: "ntp");

if (!os = get_kb_item("ntp/" + port + "/system_banner"))
  exit(0);

if ("Data ONTAP" >< os) {
  set_kb_item(name: "netapp_data_ontap/detected", value: TRUE);
  set_kb_item(name: "netapp_data_ontap/ntp/detected", value: TRUE);
  set_kb_item(name: "netapp_data_ontap/ntp/port", value: port);
  set_kb_item(name: "netapp_data_ontap/ntp/" + port + "/concluded", value: os);

  vers = eregmatch(pattern: "Data ONTAP/([0-9P.]+)", string: os);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "netapp_data_ontap/ntp/" + port + "/version", value: version);
  }
}

exit(0);

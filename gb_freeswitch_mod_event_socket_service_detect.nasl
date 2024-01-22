# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143229");
  script_version("2024-01-17T06:33:34+0000");
  script_tag(name:"last_modification", value:"2024-01-17 06:33:34 +0000 (Wed, 17 Jan 2024)");
  script_tag(name:"creation_date", value:"2019-12-05 08:18:24 +0000 (Thu, 05 Dec 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("FreeSWITCH mod_event_socket Service Detection");

  script_tag(name:"summary", value:"A FreeSWITCH mod_event_socket service is running at this host.

  mod_event_socket is a TCP-based interface to control FreeSWITCH.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 8021);

  script_xref(name:"URL", value:"https://freeswitch.org/confluence/display/FREESWITCH/mod_event_socket");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");

port = unknownservice_get_port(default: 8021);

soc = open_sock_tcp(port);
if (!soc)
  exit(0);

recv = recv(socket: soc, length: 512);
close(soc);

if (recv =~ "^Content-Type\s*:\s*auth/request" || recv =~ "^Content-Type\s*:\s*text/rude-rejection") {
  set_kb_item(name: "freeswitch/detected", value: TRUE);
  set_kb_item(name: "freeswitch/mod_event_socket/detected", value: TRUE);
  set_kb_item(name: "freeswitch/mod_event_socket/port", value: port);

  service_register(port: port, ipproto: "tcp", proto: "mod_event_socket");

  report = 'A FreeSWITCH mod_event_socket is running at this port.\n\nServer Response:\n\n' + recv;
  log_message(port: port, data: report);

  exit(0);
}

exit(0);

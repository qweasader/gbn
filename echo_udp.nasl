# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108102");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-03-24 15:43:44 +0100 (Tue, 24 Mar 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("echo Service Detection (UDP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Service detection");
  script_dependencies("gb_open_udp_ports.nasl");
  script_require_udp_ports("Services/udp/unknown", 7);

  script_tag(name:"summary", value:"Checks if the remote host is running an echo service via UDP.

  Note: The reporting takes place in a separate VT 'echo Service Reporting (TCP + UDP)' (OID: 1.3.6.1.4.1.25623.1.0.100075).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = unknownservice_get_port( default:7, ipproto:"udp" );

if( ! soc = open_sock_udp( port ) )
  exit( 0 );

vtstrings = get_vt_strings();

echo_string = vtstrings["default"] + "-Echo-Test";

send( socket:soc, data:echo_string );
buf = recv( socket:soc, length:512 );
close( soc );

if( buf == echo_string ) {
  service_register( port:port, proto:"echo", ipproto:"udp" );
  set_kb_item( name:"echo_tcp_udp/detected", value:TRUE );
  set_kb_item( name:"echo_udp/detected", value:TRUE );
  set_kb_item( name:"echo_udp/" + port + "/detected", value:TRUE );
  log_message( port:port, data:"An echo service is running at this port.", protocol:"udp" );
}

exit( 0 );

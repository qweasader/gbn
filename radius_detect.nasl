# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100254");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-07-31 12:39:44 +0200 (Fri, 31 Jul 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Radius Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Service detection");
  script_require_udp_ports(1812);

  script_tag(name:"summary", value:"The remote host is running a Radius Server.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = 1812;
ip = split( get_host_ip(), sep:".", keep:0 );
vt_strings = get_vt_strings();
username = vt_strings["default"];

data =
raw_string( 0x40, 0xfa, 0xb3, 0x17, 0x23, 0xfd, 0xe5, 0x7f,
0x4a, 0x02, 0x74, 0x55, 0x15, 0x0c, 0x45, 0xeb ) +

raw_string( 0x01, ( strlen( username ) + 2 ) ) + username +

raw_string( 0x02, 0x12, 0xfa, 0x4d, 0xb1, 0x43, 0x69, 0xd5, 0x69, 0x8b, 0x1f, 0x30,
            0xea, 0xf4, 0x54, 0x45, 0x1e, 0x70, 0x04, 0x06,
            int( ip[0] ), int( ip[1] ), int( ip[2] ), int( ip[3] ),
            0x05, 0x06, 0x00, 0x00, 0x15, 0x38 );

data = raw_string( 0x01, 0xbe, 0x00, ( strlen( data ) + 4 ) ) + data;

if( get_udp_port_state( port ) ) {
  soc = open_sock_udp(port);
  if( ! soc ) exit( 0 );

  send( socket:soc, data:data );
  buf = recv( socket:soc, length:4096 );
  if( buf && ord( buf[0] ) == 3 ) { # Radius-Code: Access-Rejected (3)
    service_register( port:port, proto:"radius", ipproto:"udp" );
    log_message( port:port, proto:"udp" );
  }
  close(soc);
}

exit( 0 );

# SPDX-FileCopyrightText: 1999 SecuriTeam
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10033");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_name("CA Unicenter's Transport Service is running");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 1999 SecuriTeam");
  script_family("Windows");
  script_dependencies("find_service.nasl");
  script_require_ports(7001, 7003);
  script_require_udp_ports(7004);

  script_tag(name:"solution", value:"Block those ports from outside communication.");

  script_tag(name:"summary", value:"CA Unicenter Transport Service uses ports TCP:7001, TCP:7003 and UDP:7004
  for communication between its clients and other CA Unicenter servers. Since
  the above ports are open, CA Unicenter's Transport service is probably
  running, and is open for outside attacks.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

if( get_port_state( 7001 ) && get_port_state( 7003 ) && get_udp_port_state( 7004 ) ) {

  soctcp = open_sock_tcp( 7001 );
  if( ! soctcp ) exit( 0 );
  else close( soctcp );

  soctcp = open_sock_tcp( 7003 );
  if( ! soctcp ) exit( 0 );
  else close( soctcp );

  socudp7004 = open_sock_udp( 7004 );

  if( socudp7004 ) {
    send( socket:socudp7004, data:"\r\n" );
    result = recv( socket:socudp7004, length:1000 );
    close( socudp7004 );
    if( strlen( result ) > 0 ) {
      security_message( port:0 );
      exit( 0 );
    }
  }
}

exit( 0 );
# SPDX-FileCopyrightText: 2005 SecuriTeam
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10617");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Check Point FireWall-1 (FW-1) SecureRemote (SecuRemote) Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("Copyright (C) 2005 SecuriTeam");
  script_dependencies("find_service.nasl", "find_service1.nasl", "find_service2.nasl", "find_service3.nasl");
  script_require_ports("Services/fw1-topology", 264);

  script_tag(name:"summary", value:"The remote host seems to be a Check Point FireWall-1 (FW-1)
  running SecureRemote (SecuRemote).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("port_service_func.inc");
include("host_details.inc");

port = service_get_port( default:264, proto:"fw1-topology" );

soc = open_sock_tcp( port );
if( ! soc )
  exit( 0 );

buf1 = raw_string( 0x41, 0x00, 0x00, 0x00 );
buf2 = raw_string( 0x02, 0x59, 0x05, 0x21 );

send( socket:soc, data:buf1 );
send( socket:soc, data:buf2 );
res = recv( socket:soc, length:5 );
close( soc );

if( res == buf1 ) {
  report = "A Check Point FireWall-1 (FW-1) SecureRemote (SecuRemote) service seems to be running on this port";
  service_register( port:port, proto:"fw1-topology", message:report );
  set_kb_item( name:"Host/firewall", value:"Check Point FireWall-1 (FW-1)" );
  log_message( port:port, data:report );
}

exit( 0 );
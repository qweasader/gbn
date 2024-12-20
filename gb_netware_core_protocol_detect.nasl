# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108316");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-01-12 08:57:15 +0100 (Fri, 12 Jan 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("NetWare Core Protocol (NCP) Detection");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 524);

  script_tag(name:"summary", value:"The script checks the presence of a service supporting the
  NetWare Core Protocol (NCP).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");
include("dump.inc");

port = unknownservice_get_port( default:524 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

# From pre2008/NDS_Object_Enum.nasl
req = raw_string( 0x44, 0x6d, 0x64, 0x54,  # NCP over IP signature: Demand Transport
                  0x00, 0x00, 0x00, 0x17,  # NCP over IP Length: 0x00000017 (23 bytes)
                  0x00, 0x00, 0x00, 0x01,  # NCP over IP version: 1
                  0x00, 0x00, 0x00, 0x00,  # NCP over IP Reply Buffer Size: 0
                  0x11, 0x11,              # Type: Create a service connection
                  0x00,                    # Initial sequence number 0x00
                  0xff,                    # Connection Number low, 0xff (255) wildcard
                  0x01,                    # Task Number: 1
                  0xff,                    # Connection Number high, 0xff (255) wildcard
                  0x04 );                  # Group: Connection

send( socket:soc, data:req );
res = recv( socket:soc, length:64 );
close( soc );

if( res && hexstr( res ) =~ "^744E635000000010333300" ) {
  set_kb_item( name:"netware/ncp/" + port + "/detected", value:TRUE );
  set_kb_item( name:"netware/ncp/detected", value:TRUE );

  service_register( port:port, proto:"ncp", message:"A service supporting the NetWare Core Protocol is running at this port." );
  log_message( port:port, data:"A service supporting the NetWare Core Protocol is running at this port." );
}

exit( 0 );

# SPDX-FileCopyrightText: 2005 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.18392");
  script_version("2023-06-27T05:05:30+0000");
  script_tag(name:"last_modification", value:"2023-06-27 05:05:30 +0000 (Tue, 27 Jun 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("IRC bot detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Michel Arboi");
  script_family("Malware");
  script_require_ports("Services/fake-identd", 113);
  script_dependencies("find_service1.nasl");

  script_tag(name:"summary", value:"This host seems to be running an ident server, but before any
  request is sent, the server gives an answer about a connection to port 6667.");

  script_tag(name:"insight", value:"It is very likely this system has heen compromised by an IRC
  bot and is now a 'zombi' that can participate into 'distributed denial of service' (DDoS).");

  script_tag(name:"solution", value:"Desinfect or re-install your system");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("port_service_func.inc");

port = service_get_port(default:113, proto:"fake-identd");
b = get_kb_item( "FindService/tcp/" + port + "/spontaneous" );
if( ! b )
  exit( 0 );

if( b =~ '^[0-9]+ *, *6667 *: *USERID *: *UNIX *: *[A-Za-z0-9]+' ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );

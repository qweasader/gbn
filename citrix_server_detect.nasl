# SPDX-FileCopyrightText: 2005 John Lampe...j_lampe@bellsouth.net
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10942");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Citrix Server Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 John Lampe...j_lampe@bellsouth.net");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports(1494);

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/7276");

  script_tag(name:"summary", value:"A Citrix server is running on this machine.");

  script_tag(name:"insight", value:"Citrix servers allow a Windows user to remotely obtain a
  graphical login (and therefore act as a local user on the remote host).

  NOTE: by default the Citrix Server application utilizes a weak 40 bit obfuscation algorithm (not
  even a true encryption).  If the default settings have not been changed, there already exists
  tools which can be used to passively ferret userIDs and passwords as they traverse a network.

  If this server is located within your DMZ, the risk is substantially higher, as Citrix necessarily
  requires access into the internal network for applications like SMB browsing, file sharing, email
  synchronization, etc.

  If an attacker gains a valid login and password, he may be able to use this service to gain
  further access on the remote host or remote network. This protocol has also been shown to be
  vulnerable to a man-in-the-middle attack.");

  script_tag(name:"solution", value:"Disable this service if you do not use it. Also, make sure
  that the server is configured to utilize strong encryption.");

  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

port = 1494;
if( ! get_port_state( port ) )
  exit( 0 );

soc = open_sock_tcp( port );
if( soc ) {

  r = recv( socket:soc, length:64 );
  if( ( egrep( pattern:".*ICA.*", string:r ) ) ) {
    log_message( port:port );
  }
  close( soc );
}

exit( 0 );
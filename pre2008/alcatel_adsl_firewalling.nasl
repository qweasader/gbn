# SPDX-FileCopyrightText: 2001 Alert4Web.com
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10760");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2001-1424", "CVE-2001-1425");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Alcatel ADSL modem with firewalling off");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2001 Alert4Web.com");
  script_family("General");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports(23); # alcatel's ADSL modem telnet module can't bind to something else

  script_xref(name:"URL", value:"http://www.alcatel.com/consumer/dsl/security.htm");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/2568");

  script_tag(name:"solution", value:"Telnet to this modem and adjust the security
  settings as follows:

  => ip config firewalling on

  => config save

  Please see the reference for more information.");

  script_tag(name:"summary", value:"On the Alcatel Speed Touch Pro ADSL modem, a protection mechanism
  feature is available to ensure that nobody can gain remote access to the modem (via the WAN/DSL interface).

  This mechanism guarantees that nobody from outside your network can access the modem and
  change its settings.

  The protection is currently not activated on your system.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

if( ! ereg( pattern:"^10\.0\.0\..*", string:get_host_ip() ) )
  exit( 0 );

port = 23; # alcatel's ADSL modem telnet module can't bind to something else
if( ! get_port_state( port ) )
  exit( 0 );

soc = open_sock_tcp( port );
if( ! soc )
  exit( 0 );

r = recv( socket:soc, length:160 );

if( "User : " >< r ) {
  send( socket:soc, data:string( "\r\n" ) );
  r = recv( socket:soc, length:2048 );
  if( "ALCATEL ADSL" >< r ) {
    s = string( "ip config\r\n" );
    send( socket:soc, data:s );
    r = recv( socket:soc, length:2048 );
    if( "Firewalling off" >< r ) {
      close( soc );
      security_message( port:port );
      exit( 0 );
    }
    close( soc );
    exit( 99 );
  }
}

close( soc );
exit( 0 );
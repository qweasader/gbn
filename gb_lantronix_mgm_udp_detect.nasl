# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108299");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-11-28 08:03:31 +0100 (Tue, 28 Nov 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Lantronix Remote Configuration Protocol Detection (UDP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Service detection");
  script_require_udp_ports(30718);

  script_tag(name:"summary", value:"A service supporting the Lantronix remote configuration protocol
  over TCP is running at this host.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("dump.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("list_array_func.inc");
include("host_details.inc");

# partly based on 2012/gb_lantronix_password_disclosure.nasl and
# https://github.com/kost/lantronix-witchcraft/blob/master/lantronix-witchcraft.pl

port = 30718;
if( ! get_udp_port_state( port ) ) exit( 0 );
soc = open_sock_udp( port );
if( ! soc ) exit( 0 );

# UDP getconfig command
getconf_req = raw_string( 0x00, 0x00, 0x00, 0xF8 );
send( socket:soc, data:getconf_req );
getconf_recv = recv( socket:soc, length:124 );

if( ! getconf_recv || strlen( getconf_recv ) != 124 || hexstr( substr( getconf_recv, 0, 3 ) ) != "000000f9" ) {
  close( soc );
  exit( 0 );
}

# UDP query command
query_req = raw_string( 0x00, 0x00, 0x00, 0xF6 );
send( socket:soc, data:query_req );
query_recv = recv( socket:soc, length:30 );
close( soc );

info = make_array();

# collect IP
for( i = 4; i < 8; i++ ) {
  if( i != 4 ) ip += ".";
  ip += string( ord( getconf_recv[i] ) );
}
info["IP"] = ip;

# collect Gateway
for( i = 16; i < 20; i++ ) {
  if( i != 16 ) gateway += ".";
  gateway += string( ord( getconf_recv[i] ) );
}
info["Gateway"] = gateway;

# collect host bits of the device
info["Host bits"] = hexstr( getconf_recv[10] );

# collect Password
for( i = 12; i < 16; i++ ) {
  pass += getconf_recv[i];
}

if( hexstr( pass ) == "00000000" ) {
  info["Password"] = "No password set/Enhanced Password enabled";
} else {
  pass = bin2string( ddata:pass, noprint_replacement:'' );
  info["Password"] = pass;
  set_kb_item( name:"lantronix_device/lantronix_remote_conf_udp/" + port + "/password", value:pass );
  set_kb_item( name:"lantronix_device/lantronix_remote_conf/password_gathered", value:TRUE );
}

if( strlen( query_recv ) == 30 ) {

  # collect type of device
  for( i = 8; i < 12; i++ ) {
    type += string( query_recv[i] );
  }
  type = bin2string( ddata:type, noprint_replacement:'' );
  info["Device Type"] = type;

  # collect the MAC address
  for( i = 24; i < 30; i++ ) {
    if( i != 24 ) mac += ":";
    mac += hexstr( query_recv[i] );
  }
  #verify the syntax of the MAC
  if( egrep( pattern:"([0-9a-fA-F:]{17})", string:mac ) ) {
    register_host_detail( name:"MAC", value:mac, desc:"Get the MAC Address via Lantronix remote configuration protocol" );
    replace_kb_item( name:"Host/mac_address", value:mac );
    info["MAC"] = mac;
  }
}

info["Port"] = port + "/udp";

set_kb_item( name:"lantronix_device/lantronix_remote_conf_udp/" + port + "/extracted", value:text_format_table( array:info ) );
set_kb_item( name:"lantronix_device/lantronix_remote_conf_udp/detected", value:TRUE );
set_kb_item( name:"lantronix_device/lantronix_remote_conf_udp/port", value:port );
set_kb_item( name:"lantronix_device/lantronix_remote_conf_udp/" + port + "/type", value:"unknown" ); # Type above doesn't match the actual device type
set_kb_item( name:"lantronix_device/lantronix_remote_conf_udp/" + port + "/version", value:"unknown" );
set_kb_item( name:"lantronix_device/detected", value:TRUE );

service_register( port:port, proto:"lantronix_remote_conf", ipproto:"udp" );

log_message( port:port, data:"A service supporting the Lantronix remote configuration protocol is running at this port.", proto:"udp" );
exit( 0 );

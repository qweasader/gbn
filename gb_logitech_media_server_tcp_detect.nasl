# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108524");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-12-28 20:35:26 +0100 (Fri, 28 Dec 2018)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Logitech SqueezeCenter/Media Server Detection (SlimProto TCP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/wrapped", 3483);

  script_tag(name:"summary", value:"Detection of a Logitech SqueezeCenter/Media Server via SlimProto TCP.

  This script sends a SlimProto TCP 'HELLO' request to the target and tries to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");
include("byte_func.inc");

port = service_get_port( default:3483, proto:"wrapped" );

soc = open_sock_tcp( port );
if( ! soc )
  exit( 0 );

# http://wiki.slimdevices.com/index.php/SlimProto_TCP_protocol
# https://github.com/Excito/squeezecenter/blob/master/HTML/EN/html/docs/slimproto.html
# https://github.com/Excito/squeezecenter/blob/master/Slim/Networking/Slimproto.pm
req  = raw_string( 0x06 );  # Assume 'softsqueeze3' in the 'DeviceID' field
req += raw_string( 0x01 );  # Assume version '1' in the 'Revision' field
req += "00:00:00:00:00:00"; # Normally our local MAC address but the server will accept any
req = "HELO" + mkdword( strlen( req ) ) + req; # Build up our request, first the HELO, then the length of the previous generated request and finally the generated request.

send( socket:soc, data:req );
res = recv( socket:soc, length:2, min:2 ); # "Data from the server to the player consists of 2 bytes of length data (in network order)"
if( ! res || strlen( res ) != 2 ) {
  close( soc );
  exit( 0 );
}

# Receive the remaining data according to what the server has told us about its length
len = getword( blob:res, pos:0 );
res = recv( socket:soc, length:len, min:len );

if( ! res || strlen( res ) != len ) {
  exit( 0 );
  close( soc );
}

# vers7.7.2
if( res =~ "^vers[0-9.]+" ) {

  version = "unknown";
  vers = eregmatch( string:res, pattern:"^vers([0-9.]+)", icase:FALSE );
  if( vers[1] ) {
    version = vers[1];
    set_kb_item( name:"logitech/squeezecenter/tcp/" + port + "/concluded", value:vers[0] );
  }

  set_kb_item( name:"logitech/squeezecenter/detected", value:TRUE );
  set_kb_item( name:"logitech/squeezecenter/tcp/detected", value:TRUE );
  set_kb_item( name:"logitech/squeezecenter/tcp/port", value:port );
  set_kb_item( name:"logitech/squeezecenter/tcp/" + port + "/detected", value:TRUE );
  set_kb_item( name:"logitech/squeezecenter/tcp/" + port + "/version", value:version );

  # nb: log_message because of the "wrapped" where we don't get any other log messages within our results.
  log_message( port:port, data:"A Logitech SqueezeCenter/Media server supporting the SlimProto protocol seems to be running on this port." );
  service_register( port:port, proto:"squeezecenter", ipproto:"tcp" );

  # Send the final "BYE" to disconnect from the service.
  req = raw_string( 0x00 ); # "If the first data byte to this command is 0x01 then the player is going out for an upgrade..." -> We don't want to go out for an upgrade...
  req = "BYE!" + mkdword( strlen( req ) ) + req;
  send( socket:soc, data:req );
}

close( soc );
exit( 0 );

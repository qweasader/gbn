# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105030");
  script_version("2023-04-18T10:19:20+0000");
  script_tag(name:"last_modification", value:"2023-04-18 10:19:20 +0000 (Tue, 18 Apr 2023)");
  script_tag(name:"creation_date", value:"2014-05-21 12:39:47 +0100 (Wed, 21 May 2014)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("AMQP Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 5672);

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts
  to determine if AMQP is supported.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");

port = unknownservice_get_port( default:5672 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

req = raw_string( 'AMQP', 0, 0, 0, 0 );

send( socket:soc, data:req );
buf = recv( socket:soc, min:8, length:128 );
close( soc );

if( ! buf || isnull( buf ) || strlen( buf ) != 8 || substr( buf, 0, 3 ) != 'AMQP' ) exit( 0 );

service_register( port:port, proto:"amqp" );

pv = ord( buf[4] );
version = ord( buf[5] ) + '.' + ord( buf[6] ) + '.' + ord( buf[7] );

protocol = 'unknown';

if      ( pv == 0 ) protocol = 'Basic';
else if ( pv == 2 ) protocol = 'STARTTLS';
else if ( pv == 3 ) protocol = 'SASL';

set_kb_item( name:"amqp/" + port + "/protocol", value:pv );
set_kb_item( name:"amqp/" + port + "/version", value:version );
set_kb_item( name:"amqp/" + port + "/version/raw", value:buf[5] + buf[6] + buf[7] );
set_kb_item( name:"amqp/installed", value:TRUE );

report = 'An AMQP server is running on this host.\n\nVersion:  ' + version + '\nProtocol: ' + protocol + '\n';
log_message( port:port, data:report );

exit( 0 );

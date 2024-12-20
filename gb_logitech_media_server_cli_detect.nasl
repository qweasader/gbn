# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108518");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-12-12 18:08:58 +0100 (Wed, 12 Dec 2018)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Logitech SqueezeCenter/Media Server CLI Detection");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_dependencies("find_service4.nasl");
  script_require_ports("Services/squeezecenter_cli", "9090");

  script_tag(name:"summary", value:"The script tries to identify services supporting
  Logitech SqueezeCenter/Media Server CLI interface.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");

port = service_get_port( default:9090, proto:"squeezecenter_cli" );

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

# http://wiki.slimdevices.com/index.php/CLI
send( socket:soc, data:'serverstatus\r\n' );
res = recv( socket:soc, length:512 );
close( soc );

if( ! res || "serverstatus" >!< res )
  exit( 0 );

# serverstatus   lastscan%3A0 version%3A7.7.2 uuid%3A3aab3e11-c2d7-4ffb-b2af-be171784d6b5 info%20total%20albums%3A0 info%20total%20artists%3A0 info%20total%20genres%3A0 info%20total%20songs%3A0 player%20count%3A0 sn%20player%20count%3A0 other%20player%20count%3A0
# nb: Choosing a few additional || pattern so we're catching more possible variants
# without risking to do a false detection.
if( egrep( string:res, pattern:"^serverstatus\s+", icase:FALSE ) &&
    ( " lastscan%3A" >< res || " version%3A" >< res || " uuid%3A" >< res || "player%20count%3A" >< res ) &&
    ( " info%20total%20albums%3A" >< res || " info%20total%20artists%3A" >< res || " info%20total%20genres%3A" >< res || " info%20total%20songs%3A" >< res ) ) {

  res = chomp( res );

  version = "unknown";
  vers = eregmatch( string:res, pattern:"version%3A([0-9.]+) ", icase:FALSE );
  if( vers[1] )
    version = vers[1];

  set_kb_item( name:"logitech/squeezecenter/detected", value:TRUE );
  set_kb_item( name:"logitech/squeezecenter/cli/detected", value:TRUE );
  set_kb_item( name:"logitech/squeezecenter/cli/port", value:port );
  set_kb_item( name:"logitech/squeezecenter/cli/" + port + "/detected", value:TRUE );
  set_kb_item( name:"logitech/squeezecenter/cli/" + port + "/version", value:version );
  set_kb_item( name:"logitech/squeezecenter/cli/" + port + "/concluded", value:res );

  log_message( port:port, data:"A service supporting the Logitech SqueezeCenter/Media Server CLI interface seems to be running on this port." );
  service_register( port:port, proto:"squeezecenter_cli", message:"A service supporting the Logitech SqueezeCenter/Media Server CLI interface seems to be running on this port." );
}

exit( 0 );

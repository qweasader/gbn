# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105332");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-08-27 14:44:28 +0200 (Thu, 27 Aug 2015)");
  script_name("Cisco TelePresence Video Communication Server Detection (SIP)");

  script_tag(name:"summary", value:"The script sends a connection
  request to the server and attempts to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("sip_detection.nasl", "sip_detection_tcp.nasl");
  script_mandatory_keys("sip/banner/available");

  exit(0);
}

include("host_details.inc");
include("sip.inc");
include("misc_func.inc");
include("port_service_func.inc");

infos = sip_get_port_proto( default_port:"5060", default_proto:"udp" );
port = infos["port"];
proto = infos["proto"];

if( ! banner = sip_get_banner( port:port, proto: proto ) )
  exit( 0 );

if( "TANDBERG/4" >!< banner )
  exit( 0 );

# https://supportforums.cisco.com/document/12270151/sip-user-agents-ua-telepresence
valid_devices = make_list( "TANDBERG/4132", "TANDBERG/4131", "TANDBERG/4130", "TANDBERG/4129", "TANDBERG/4120", "TANDBERG/4103", "TANDBERG/4102", "TANDBERG/4352", "TANDBERG/4481" );
foreach device( valid_devices ) {
  if( device >< banner ) {
    device_is_valid = TRUE;
    break;
  }
}

if( ! device_is_valid )
  exit( 0 );

vers = "unknown";
model = "unknown";
cpe = "cpe:/a:cisco:telepresence_video_communication_server_software";

version = eregmatch( pattern:'TANDBERG/([^ ]+) \\(X([^-)]+)\\)', string:banner );
if( ! isnull( version[1] ) ) {
  model = version[1];
  set_kb_item( name:"cisco_vcs/sip/model", value:model );
}

if( ! isnull( version[2] ) ) {
  vers = version[2];
  cpe += ":" + vers;
  set_kb_item( name:"cisco_vcs/sip/version", value:vers );
}

set_kb_item( name:"cisco_vcs/installed",value:TRUE );

location = port + "/" + proto;

register_product(cpe: cpe, port: port, location: location, service: "sip", proto: proto);

log_message( data: build_detection_report( app:"Cisco TelePresence Video Communication Server (" + model + ")",
                                           version:vers,
                                           install:location,
                                           cpe:cpe,
                                           concluded: version[0] ),
             port:port, proto:proto );

exit(0);

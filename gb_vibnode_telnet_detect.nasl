# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108339");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-02-15 16:10:41 +0100 (Thu, 15 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("PRUFTECHNIK VIBNODE Detection (Telnet)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/pruftechnik/vibnode/detected");

  script_tag(name:"summary", value:"The script sends a Telnet connection request to the remote
  host and attempts to detect the presence of a PRUFTECHNIK VIBNODE device and to extract its version.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("telnet_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("dump.inc");

port = telnet_get_port( default:23 );
banner = telnet_get_banner( port:port );

# Welcome to VibNode.   (1.15   VN-070926-b02)
# Welcome to VIBNODE.  (VN-3.4.2-110303-b01 / OS_1.15)
if( "Welcome to V" >< banner && ( "VibNode" >< banner || "VIBNODE" >< banner ) ) {

  app_version = "unknown";
  os_version  = "unknown";
  set_kb_item( name:"vibnode/detected", value:TRUE );
  set_kb_item( name:"vibnode/telnet/detected", value:TRUE );
  set_kb_item( name:"vibnode/telnet/port", value:port );

  app_vers = eregmatch( pattern:"Welcome to VIBNODE\..*\(VN-([0-9.]+)", string:banner );
  if( ! isnull( app_vers[1] ) ) app_version = app_vers[1];

  os_vers = eregmatch( pattern:"Welcome to VIBNODE\..*( \(| / OS_)([0-9.]+)", string:banner, icase:TRUE );
  if( ! isnull( os_vers[2] ) ) os_version = os_vers[2];

  set_kb_item( name:"vibnode/telnet/" + port + "/concluded", value:banner );
  set_kb_item( name:"vibnode/telnet/" + port + "/app_version", value:app_version );
  set_kb_item( name:"vibnode/telnet/" + port + "/os_version", value:os_version );
}

exit( 0 );

# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140096");
  script_version("2023-06-22T10:34:15+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-06-22 10:34:15 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"creation_date", value:"2016-12-12 12:33:00 +0100 (Mon, 12 Dec 2016)");
  script_name("Check_MK Agent Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("find_service5.nasl");
  script_require_ports("Services/check_mk_agent", 6556);

  script_tag(name:"summary", value:"This script performs detection of a Check_MK agent.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("port_service_func.inc");
include("host_details.inc");
include("os_func.inc");

SCRIPT_DESC = "Check_MK Agent Detection";
banner_type = "Check_MK AgentOS report";

if( ! port = service_get_port( default:6556, proto:"check_mk_agent" ) )
  exit( 0 );

if( ! buf = get_kb_item( "check_mk_agent/banner/" + port ) ) {

  if( ! soc = open_sock_tcp( port ) )
    exit( 0 );

  buf = recv( socket:soc, length:2048 );
  close( soc );
  notinkb = TRUE;
}

if( "<<<check_mk>>>" >!< buf && "<<<uptime>>>" >!< buf && "<<<services>>>" >!< buf && "<<<mem>>>" >!< buf )
  exit( 0 );

if( notinkb )
  replace_kb_item( name:"check_mk_agent/banner/" + port , value:buf );

set_kb_item( name:"check_mk/agent/installed", value:TRUE );
set_kb_item( name:"check_mk/detected", value:TRUE );
vers = "unknown";

service_register( port:port, proto:"check_mk_agent" );

av = eregmatch( pattern:'Version: ([0-9.]+[^ \r\n]+)', string:buf );

if( ! isnull( av[1] ) ) {
  set_kb_item( name:"check_mk/agent/version", value:av[1] );
  vers = av[1];
}

extra = 'Gathered info (truncated):\n\n' + substr( buf, 0, 2000 ) + '\n[...]\n\n';

os = eregmatch( pattern:'AgentOS: ([a-zA-Z]+[^ \r\n]+)', string:buf );
if( os[1] ) {
  if( os[1] == "windows" ) {
    os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, banner:os[0], port:port, desc:SCRIPT_DESC, runs_key:"windows" );
  } else if( os[1] == "linux" ) {
    os_register_and_report( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, banner:os[0], port:port, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( os[1] == "aix" ) {
    os_register_and_report( os:"IBM AIX", cpe:"cpe:/o:ibm:aix", banner_type:banner_type, banner:os[0], port:port, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    # nb: Setting the runs_key to unixoide makes sure that we still schedule VTs using Host/runs_unixoide as a fallback
    os_register_and_report( os:os[1], banner_type:banner_type, banner:os[0], port:port, desc:SCRIPT_DESC, runs_key:"unixoide" );
    os_register_unknown_banner( banner:os[0], banner_type_name:banner_type, banner_type_short:"check_mk_agent_banner", port:port );
  }
}

cpe = "cpe:/a:check_mk_project:check_mk";
if( vers != "unknown" )
  cpe += ":" + tolower( vers );

register_product( cpe:cpe, location:port + "/tcp", port:port, service:"check_mk_agent" );

report = build_detection_report( app:"Check_MK Agent",
                                 version:vers,
                                 cpe:cpe,
                                 extra:extra,
                                 install:port + "/tcp" );
log_message( port:port, data:report );

exit( 0 );

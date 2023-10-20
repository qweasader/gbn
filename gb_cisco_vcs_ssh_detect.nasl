# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105804");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-07-11 11:45:51 +0200 (Mon, 11 Jul 2016)");
  script_name("Cisco TelePresence Video Communication Server Detection (SSH)");

  script_tag(name:"summary", value:"This script performs SSH based detection of Cisco VCS.");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("cisco/ssh/vcs");
  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");

if( ! get_kb_item( "cisco/ssh/vcs" ) ) exit( 0 );

sock = ssh_login_or_reuse_connection();
if( ! sock ) exit( 0 );

uname = get_kb_item( "ssh/login/uname" );
if( ! uname || "TANDBERG Video Communication Server" >!< uname ) exit( 0 );

cpe = 'cpe:/a:cisco:telepresence_video_communication_server_software';
vers = 'unknown';

version = eregmatch( pattern:'TANDBERG Video Communication Server X([0-9.]+[^\r\n]+)', string:uname );
if( ! isnull( version[1] ) )
{
  vers = version[1];
  set_kb_item( name:"cisco_vcs/ssh/version", value:vers );
  cpe += ':' + vers;
}

register_product( cpe:cpe, location:'ssh', service:'ssh' );
set_kb_item( name:'cisco_vcs/installed', value:TRUE );

log_message( data: build_detection_report( app:"Cisco TelePresence Video Communication Server",
                                           version:vers,
                                           install:'ssh',
                                           cpe:cpe,
                                           concluded: version[0] ),
             port:0 );

xstatus = ssh_cmd( socket:sock, cmd:'xstatus', return_errors:TRUE, nosh:TRUE, pty:TRUE, timeout:20, retry:20, pattern:'\\*s/end[\r\n]+OK');
if( xstatus )
{
  set_kb_item( name:"cisco_vcs/ssh/xstatus", value:xstatus );
  lines = split( xstatus );
  foreach line ( lines )
  {
    if( line == '*s SystemUnit: /') su = TRUE;
    if( su && line == '*s/end' ) break;

    if( b = eregmatch( pattern:'Build: "([^"]+)"', string:line ) )
    {
      set_kb_item( name:'cisco_vcs/ssh/build', value:b[1]);
      build = b[1];
    }

  }
}

exit( 0 );


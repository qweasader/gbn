# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804786");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-11-04 16:38:25 +0530 (Tue, 04 Nov 2014)");
  script_name("Windows Services Start");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Windows");
  # Don't add a dependency to os_detection.nasl. This will cause a dependency cycle.
  script_dependencies("toolcheck.nasl", "smb_login.nasl", "smb_nativelanman.nasl", "netbios_name_get.nasl", "lsc_options.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/login", "SMB/password", "Tools/Present/wmi");
  script_exclude_keys("SMB/samba");

  script_tag(name:"summary", value:"This routine starts not running (but required) windows services before launching an
  authenticated scan.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");

if( ! defined_func( "win_cmd_exec" ) )
  exit( 0 );

if( get_kb_item( "win/lsc/disable_win_cmd_exec" ) )
  win_cmd_exec_disabled = TRUE;

function run_command( command, password, username, service ) {

  local_var command, password, username, service, serQueryRes, serStat;

  if( win_cmd_exec_disabled ) {
    set_kb_item( name:service + "/Win/Service/Manual/Failed", value:"Usage of win_cmd_exec required to start this service was disabled manually within 'Options for Local Security Checks (OID: 1.3.6.1.4.1.25623.1.0.100509)'." );
    return;
  }

  serQueryRes = win_cmd_exec( cmd:command, password:password, username:username );

  if( "Access is denied" >< serQueryRes ) {
    set_kb_item( name:service + "/Win/Service/Manual/Failed", value:chomp( serQueryRes ) );
    return;
  } else if( "The specified service does not exist" >< serQueryRes ) {
    set_kb_item( name:service + "/Win/Service/Manual/Failed", value:chomp( serQueryRes ) );
    return;
  } else if( "The service cannot be started" >< serQueryRes && "it is disabled" >< serQueryRes ) {
    set_kb_item( name:service + "/Win/Service/Manual/Failed", value:chomp( serQueryRes ) );
    return;
  } else if( "OpenService FAILED" >< serQueryRes && "specified service does not exist" >< serQueryRes ) {
    set_kb_item( name:service + "/Win/Service/Manual/Failed", value:chomp( serQueryRes ) );
    return;
  } else if( "StartService FAILED" >< serQueryRes ) {
    set_kb_item( name:service + "/Win/Service/Manual/Failed", value:chomp( serQueryRes ) );
    return;
  } else if( "An instance of the service is already running" >< serQueryRes ) {
    set_kb_item( name:service + "/Win/Service/Manual/Failed", value:chomp( serQueryRes ) );
    return;
  } else {
    if( "SERVICE_NAME" >< serQueryRes && "STATE" >< serQueryRes && "SERVICE_EXIT_CODE" >< serQueryRes ) {
      serStat = eregmatch( pattern:"STATE.*: [0-9]  ([a-zA-Z_]+)", string:serQueryRes );
      return serStat[1];
    }
    if( isnull( serQueryRes ) ) serQueryRes = "win_cmd_exec failed for unknown reasons. Please check the scanners logfiles for more info.";
    set_kb_item( name:service + "/Win/Service/Manual/Failed", value:chomp( serQueryRes ) );
    return;
  }
}

if( kb_smb_is_samba() ) exit( 0 );

port = kb_smb_transport();
if( ! port ) port = 139;
if( ! get_port_state( port ) ) exit( 0 );

username = kb_smb_login();
password = kb_smb_password();
if( ! username && ! password ) exit( 0 );

domain = kb_smb_domain();
if( domain ) username = domain + "/" + username;

service_list = make_list( "RemoteRegistry" );

foreach service( service_list ) {

  cmd = "cmd /c sc query " + service;
  serQueryStat = run_command( command:cmd, password:password, username:username, service:service );

  if( "STOPPED" >< serQueryStat ) {

    cmd = "cmd /c sc start " + service;
    serQueryStat = run_command( command:cmd, password:password, username:username, service:service );

    if( "START_PENDING" >< serQueryStat ) {

      cmd = "cmd /c sc query " + service;
      serQueryStat = run_command( command:cmd, password:password, username:username, service:service );

      if( "RUNNING" >< serQueryStat ) {
        set_kb_item( name:service + "/Win/Service/Manual/Start", value:TRUE );
      }
    }
  }
}

exit( 0 );

# SPDX-FileCopyrightText: 2003 Douglas Minderhout
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11201");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Nortel/Bay Networks/Xylogics Annex Default Password (Telnet)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2003 Douglas Minderhout");
  script_family("Default Accounts");
  script_dependencies("telnetserver_detect_type_nd_version.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/nortel_bay_networks/annex/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"solution", value:"Telnet to this terminal server change to the root user with
  'su' and set the password with the 'passwd' command. Then, go to the admin mode using the 'admin'
  command. Cli security can then be enabled by setting the vcli_security to 'Y' with the command
  'set annex vcli_security Y'. This will require ERPCD or RADIUS authentication for access to the
  terminal server. Changes can then be applied through the 'reset annex all' command.");

  script_tag(name:"summary", value:"The remote terminal server has the default password set.");

  script_tag(name:"impact", value:"If modems are attached to this terminal server, it may allow
  unauthenticated remote access to the network.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("telnet_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("dump.inc");

function myrecv( socket, pattern ) {

  local_var socket, pattern;

  while( 1 ) {
    r = recv_line( socket:socket, length:1024 );
    if( strlen( r ) == 0 ) return( 0 );
    if( ereg( pattern:pattern, string:r ) ) return( r );
  }
}

port = telnet_get_port( default:23 );

banner = telnet_get_banner( port:port );
if ( ! banner || "Annex" >!< banner ) exit( 0 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );
buf = telnet_negotiate( socket:soc );

nudge = string( "\r\n" );
send( socket:soc, data:nudge );

# Since the Annex is unkind enough to not send a login banner, we nudge the remote host and see if it's an Annex
# The response to the nudge should be a list of ports and a line with the word Annex in it.
resp = recv( socket:soc, length:1024 );

# If we catch one of these, it's something else
if( "NetLogin:" >< resp || "Login:" >< resp ) {
  close( soc );
  exit( 0 );
}

# If we get Annex in the response we're in business
if( "Annex" >< resp ) {

  # Here we send it the cli command, requesting a command prompt
  test = string( "cli\r\n" );
  send( socket:soc, data:test );

  resp = myrecv( socket:soc, pattern:".*annex:.*" );
  if( "annex:" >< resp ) {

    # If we get here, it means that CLI security is disabled and the annex does not require a password
    report = string( "CLI Security is disabled on the Annex" );
    security_message( port:port, data:report );

    # Now we try to 'su'
    test = string( "su\r\n" );
    send( socket:soc, data:test );

    resp = myrecv( socket:soc, pattern:".*assword:.*" );
    if( "assword:" >< resp ) {
      # The default 'su' password is the IP address of the box
      ip = get_host_ip();
      test = string( ip,"\r\n" );
      send( socket:soc, data:test );
      resp = myrecv( socket:soc, pattern:".*annex#.*" );

      if( "annex#" >< resp ) {
        # The prompt changes to 'annex#' when we're supeuser
        report = string( "The SuperUser password is at it's default setting." );
        security_message( port:port, data:report );
      }
    }
  }
  close( soc );
}

exit( 99 );

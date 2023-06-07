###############################################################################
# OpenVAS Vulnerability Test
#
# NTP(d) Server Detection
#
# Authors:
# David Lodge
# Changes by rd:
# - recv() only receives the first two bytes of data (instead of 1024)
# - replaced ord(result[0]) == 0x1E by ord(result[0]) & 0x1E (binary AND)
#
# Copyright:
# Copyright (C) 2005 David Lodge
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10884");
  script_version("2023-03-07T10:19:54+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-03-07 10:19:54 +0000 (Tue, 07 Mar 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_name("Network Time Protocol (NTP) / NTPd Detection (Remote)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 David Lodge");
  script_family("Product detection");
  script_require_udp_ports("Services/udp/ntp", 123);

  script_tag(name:"summary", value:"Detection of services supporting the Network Time Protocol
  (NTP). In addition to the protocol itself the existence of the ntpd (NTPd) daemon is detected
  as well.");

  script_tag(name:"insight", value:"It is possible to determine a lot of information about the
  remote host by querying the NTP variables - these include OS descriptor, and time settings.");

  script_tag(name:"solution", value:"Quickfix: Restrict default access to ignore all info packets.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("dump.inc");

function ntp_read_list( port ) {

  local_var port;
  local_var data, soc, r, no_bin, p;

  data = raw_string( 0x16, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00 );
  soc = open_sock_udp( port );
  if( ! soc )
    return NULL;

  send( socket:soc, data:data );
  r = recv( socket:soc, length:4096 );
  close( soc );

  if( ! r )
    return NULL;

  # From https://scan.shadowserver.org/ntpversion/:
  # If you would like to test your own device to see if it supports Mode 6 queries, try the command:
  # "ntpq -c rv [IP]". If the command is successful, you will see a string of information from the
  # IP that you queried that usually starts off with something like this:
  # 'associd=0 status=0615 leap_none, sync_ntp, 1 event, clock_sync, version="ntpd 4.2.6p2@1.2194-o Sun Oct 17 13:35:13 UTC 2010 (1)", processor="x86_64", system="Linux/3.2.0-0.bpo.4-amd64", leap=00'.
  # If any of the strings are included we're assuming that Mode 6 is enabled (for 2021/gb_ntp_mode6_response_check.nasl)
  no_bin = bin2string( ddata:r, noprint_replacement:"" );
  if( egrep( string:no_bin, pattern:"(associd|status|version|processor|system|leap)=.+", icase:TRUE ) ) {
    set_kb_item( name:"ntp/mode6/response/received", value:TRUE );
    set_kb_item( name:"ntp/mode6/response/" + port + "/received", value:TRUE );
    set_kb_item( name:"ntp/mode6/response/" + port + "/sent_data_len", value:strlen( data ) );
    set_kb_item( name:"ntp/mode6/response/" + port + "/recv_data_len", value:strlen( r ) );
  }

  p = strstr( r, "version=" );
  if( ! p )
    p = strstr( r, "processor=" );

  if( ! p )
    p = strstr( r, "system=" );

  p = ereg_replace( string:p, pattern:raw_string( 0x22 ), replace:"'" );

  if( p )
    return( p );

  return NULL;
}

function ntp_installed( port ) {

  local_var port;
  local_var data, soc, r;

  data = raw_string( 0xDB, 0x00, 0x04, 0xFA, 0x00, 0x01, 0x00, 0x00,
                     0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0xBE, 0x78, 0x2F, 0x1D, 0x19, 0xBA, 0x00, 0x00 );

  soc = open_sock_udp( port );
  if( ! soc )
    return NULL;

  send( socket:soc, data:data );
  r = recv( socket:soc, length:4096 );
  close( soc );

  if( strlen( r ) > 10 )
    return( r );

  return NULL;
}

port = service_get_port( default:123, ipproto:"udp", proto:"ntp" );

r = ntp_installed( port:port );

if( r ) {

  set_kb_item( name:"ntp/remote/detected", value:TRUE );
  set_kb_item( name:"ntp/detected", value:TRUE );

  service_register( port:port, proto:"ntp", ipproto:"udp" );

  list = ntp_read_list( port:port );
  if( ! list ) {
    log_message( port:port, protocol:"udp" );
  } else {

    set_kb_item( name:"ntp/" + port + "/full_banner", value:list );
    set_kb_item( name:"ntp/full_banner/available", value:TRUE );

    if( "system=" >< list ) {

      system_line = egrep( pattern:"system=", string:list );
      os = ereg_replace( string:system_line, pattern:".*system='?([^',]+)[',].*", replace:"\1" );

      set_kb_item( name:"ntp/system_banner/available", value:TRUE );
      set_kb_item( name:"ntp/" + port + "/system_banner", value:os );
    }

    if( "processor=" >< list ) {

      processor_line = egrep( pattern:"processor=", string:list );
      processor = ereg_replace( string:processor_line, pattern:".*processor='?([^',]+)[',].*", replace:"\1" );

      set_kb_item( name:"Host/processor/ntp", value:processor );
      set_kb_item( name:"ntp/processor_banner/available", value:TRUE );
      set_kb_item( name:"ntp/" + port + "/processor_banner", value:processor );

      register_host_detail( name:"cpuinfo", value:processor, desc:"NTP(d) Server Detection" );
    }

    if( "version=" >< list ) {

      version_line = eregmatch( pattern:"version='([^']+)',", string:list );
      if( ! isnull( version_line[1] ) ) {
        set_kb_item( name:"ntp/version_banner/available", value:TRUE );
        set_kb_item( name:"ntp/" + port + "/version_banner", value:version_line[1] );
      }
    }

    if( "ntpd" >< list ) {

      set_kb_item( name:"ntpd/remote/detected", value:TRUE );
      set_kb_item( name:"ntpd/detected", value:TRUE );

      install = port + "/udp";
      version = "unknown";
      CPE = "cpe:/a:ntp:ntp";

      # ntpd 4.1.1a@1.791 Wed Feb  5 17:54:41 PST 2003 (42)
      # ntpd 4.2.4p0@1.1472 Thu Sep  9 05:32:12 UTC 2010 (1)
      # ntpd 4.2.6p5@1.2349-o Mon May 19 11:25:49 UTC 2014 (1)
      # ntpd 4.2.0-a Wed Apr 10 19:15:06  2019 (1)
      vers = eregmatch( pattern:".*ntpd ([0-9.]+)([a-z][0-9]*)?-?((RC|beta)[0-9]+)?", string:list );
      if( ! isnull( vers[1] ) ) {
        if( vers[2] =~ "[a-z][0-9]+" && vers[3] =~ "(RC|beta)" ) {
          version = vers[1] + vers[2] + " " + vers[3];
          CPE += ":" + vers[1] + ":" + vers[2] + "-" + vers[3];
        } else if( vers[2] =~ "[a-z][0-9]*" ) {
          version = vers[1] + vers[2];
          CPE += ":" + vers[1] + ":" + vers[2];
        } else {
          version = vers[1];
          CPE += ":" + vers[1];
        }
      }

      if( version && version != "unknown" ) {

        CPE = tolower( CPE );
        set_kb_item( name:"ntpd/version/detected", value:TRUE );
        set_kb_item( name:"ntpd/version", value:version );
        set_kb_item( name:"ntpd/" + port + "/version", value:version );

        set_kb_item( name:"ntpd/remote/version/detected", value:TRUE );
        set_kb_item( name:"ntpd/remote/version", value:version );
        set_kb_item( name:"ntpd/remote/" + port + "/version", value:version );
      }

      register_product( cpe:CPE, location:install, port:port, service:"ntp", proto:"udp" );

      report = build_detection_report( app:"NTPd",
                                       version:version,
                                       install:install,
                                       cpe:CPE,
                                       concluded:vers[0] );
    }

    if( report )
      report += '\n\n';

    report += 'It was possible to gather the following information from the remote NTP host:\n\n' + chomp( list );
    log_message( port:port, proto:"udp", data:report );
    exit( 0 );
  }
}

exit( 0 );
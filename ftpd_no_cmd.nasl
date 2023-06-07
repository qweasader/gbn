###############################################################################
# OpenVAS Vulnerability Test
#
# Fake FTP server does not accept any command
#
# Authors:
# Michel Arboi <mikhail@nessus.org>
#
# Copyright:
# Copyright (C) 2008 Michel Arboi
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
  script_oid("1.3.6.1.4.1.25623.1.0.80064");
  script_version("2021-03-19T08:52:49+0000");
  script_tag(name:"last_modification", value:"2021-03-19 08:52:49 +0000 (Fri, 19 Mar 2021)");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("FTP server does not accept any command");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("Copyright (C) 2008 Michel Arboi");
  script_dependencies("find_service.nasl", "find_service_3digits.nasl", "find_service2.nasl");
  script_require_ports("Services/ftp", 21);

  script_tag(name:"insight", value:"The remote server advertises itself as being a FTP server, but it does
  not accept any command, which indicates that it may be a backdoor or a proxy.

  Further FTP tests on this port will be disabled to avoid false alerts.");

  script_tag(name:"summary", value:"The remote FTP service is not working properly.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("list_array_func.inc");
include("port_service_func.inc");
include("ftp_func.inc");

report_array = make_array();

port = ftp_get_port( default:21 );

soc = open_sock_tcp( port );
if( ! soc )
  exit( 0 );

r = ftp_recv_line( socket:soc, retry:3 );
ftp_close( socket:soc );
if( ! r ) {
  set_kb_item( name:"ftp/" + port + "/broken", value:TRUE );
  set_kb_item( name:"ftp/" + port + "/no_banner", value:TRUE );
  exit( 0 );
}

if( r =~ "^[45][0-9][0-9][ -]" || match( string:r, pattern:"Access denied*", icase:TRUE ) ) {
  set_kb_item( name:"ftp/" + port + "/denied", value:TRUE );
  exit( 0 );
}

accepted = 0;

# nb: Don't use QUIT, as some servers close the connection without a 2xx code.
foreach cmd( make_list( "HELP", "USER ftp" ) ) {

  r = ftp_get_cmd_banner( port:port, cmd:cmd, retry:3, return_errors:TRUE );
  if( r =~ "^[1-5][0-9][0-9][ -]" )
    accepted++;

  if( ! r )
    r = "No response after three retries";

  report_array[cmd] = str_replace( string:r, find:'\r\n', replace:"<newline>" );
}

if( accepted < 2 ) {
  report = "The following invalid responses have been received:";
  report += '\n\n' + text_format_table( array:report_array, sep:" | ", columnheader:make_list( "Command", "Response" ) );
  log_message( port:port, data:report );
  set_kb_item( name:"ftp/" + port + "/broken", value:TRUE );
}

exit( 0 );

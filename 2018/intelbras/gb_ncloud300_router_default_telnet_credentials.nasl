###############################################################################
# OpenVAS Vulnerability Test
#
# Intelbras NCLOUD 300 Router Default Telnet Credentials
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108492");
  script_version("2023-03-01T10:20:05+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Intelbras NCLOUD 300 Router Default Credentials (Telnet)");
  script_tag(name:"last_modification", value:"2023-03-01 10:20:05 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"creation_date", value:"2018-11-29 09:14:30 +0100 (Thu, 29 Nov 2018)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_dependencies("telnetserver_detect_type_nd_version.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/banner/available");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/44637/");

  script_tag(name:"summary", value:"Intelbras NCLOUD 300 Router have a default telnet password set.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain full
  access to sensitive information.");

  script_tag(name:"vuldetect", value:"Connects to the telnet service and tries to login with default
  username and password.");

  script_tag(name:"solution", value:"It is recommended to set a new password for the telnet access.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("telnet_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("dump.inc");

port = telnet_get_port( default:23 );
banner = telnet_get_banner( port:port );

# e.g. "WORKGROUP login: "
if( ! banner || banner !~ ".+ login: " )
  exit( 0 );

username = "root";
password = "cary";

soc = open_sock_tcp( port );
if( ! soc )
  exit( 0 );

recv = recv( socket:soc, length:128 );
if( ! recv || recv !~ ".+ login: " ) {
  close( soc );
  exit( 0 );
}

send( socket:soc, data:username + '\r\n' );
recv = recv( socket:soc, length:128 );
if( ! recv || "Password: " >!< recv ) {
  close( soc );
  exit( 0 );
}

send( socket:soc, data:password + '\r\n' );
recv = recv( socket:soc, length:128 );
close( soc );

if( recv && "BusyBox" >< recv && "built-in shell" >< recv ) {
  security_message( port:port, data:"It was possible to gain telnet access via the username '" + username + "' and the default password '" + password + "'." );
  exit( 0 );
}

exit( 99 );

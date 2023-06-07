###############################################################################
# OpenVAS Vulnerability Test
#
# FsSniffer Detection
#
# Authors:
# Joseph Mlodzianowski <joseph@rapter.net>
#
# Copyright:
# Copyright (C) 2005 J.Mlodzianowski
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
  script_oid("1.3.6.1.4.1.25623.1.0.11854");
  script_version("2022-06-01T21:00:42+0000");
  script_tag(name:"last_modification", value:"2022-06-01 21:00:42 +0000 (Wed, 01 Jun 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("FsSniffer Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 J.Mlodzianowski");
  script_family("Malware");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/RemoteNC");

  script_xref(name:"URL", value:"http://www.rapter.net/jm1.htm");

  script_tag(name:"solution", value:"See the references for details on removal.");
  script_tag(name:"impact", value:"An attacker may use it to steal your passwords.");
  script_tag(name:"summary", value:"This host appears to be running FsSniffer on this port.

  FsSniffer is backdoor which allows an intruder to steal
  PoP3/FTP and other passwords you use on your system.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}
include("port_service_func.inc");

port = service_get_port( nodefault:TRUE, proto:"RemoteNC" );

if( port ) security_message( port:port );

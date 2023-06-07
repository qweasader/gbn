###############################################################################
# OpenVAS Vulnerability Test
#
# SSF Detection
#
# Authors:
# Michel Arboi
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
  script_oid("1.3.6.1.4.1.25623.1.0.113760");
  script_version("2020-10-01T11:33:30+0000");
  script_tag(name:"last_modification", value:"2020-10-01 11:33:30 +0000 (Thu, 01 Oct 2020)");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");

  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("SSF Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Michel Arboi");
  script_family("Service detection");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/ssf/detected");

  script_xref(name:"URL", value:"http://ccweb.in2p3.fr/secur/ssf/");
  script_xref(name:"URL", value:"http://perso.univ-rennes1.fr/bernard.perrot/SSF/");

  script_tag(name:"summary", value:"Checks whether SSF is exposed on the target system.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ssh_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ssh_get_port( default:22 );
banner = ssh_get_serverbanner( port:port );
if( ! banner )
  exit( 0 );

if( egrep( string:banner, pattern:"^SSH-[0-9.]+-SSF" ) ) {
  set_kb_item( name: "ssf/detected", value: TRUE );
  set_kb_item( name: "ssf/port", value: port );
  exit( 0 );
}

exit( 99 );

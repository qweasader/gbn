###############################################################################
# OpenVAS Vulnerability Test
#
# LinuxConf grants network access
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
# Modified by Renaud Deraison <deraison@cvs.nessus.org>
#
# Copyright:
# Copyright (C) 2005 SecuriTeam
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113761");
  script_version("2020-11-10T09:46:51+0000");
  script_tag(name:"last_modification", value:"2020-11-10 09:46:51 +0000 (Tue, 10 Nov 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("LinuxConf Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 SecuriTeam");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/linuxconf", 98);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Linuxconf is running (Linuxconf is a sophisticated administration
  tool for Linux) and is granting network access at least to the host that the scanner is running on.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

CPE = "cpe:/a:jacques_gelinas:linuxconf:";

include( "host_details.inc" );
include( "misc_func.inc" );
include( "port_service_func.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );
include( "cpe.inc" );

port = service_get_port( proto:"linuxconf", default:98 );

banner = http_get_cache( item:"/", port:port );

if( "Server: linuxconf" >< banner ) {

  set_kb_item( name:"linuxconf/detected", value:TRUE );
  resultrecv = strstr( banner, "Server: " );
  resultsub  = strstr( resultrecv, string("\n"));
  resultrecv = resultrecv - resultsub;
  resultrecv = resultrecv - "Server: ";
  resultrecv = resultrecv - "\n";

  version = "unknown";

  ver = eregmatch( string:resultrecv, pattern:"([0-9.]+)" );
  if( !isnull( ver[1] ) )
    version = ver[1];

  register_and_report_cpe( app:"LinuxConf",
                           ver:version,
                           concluded:ver[0],
                           base:CPE,
                           expr:'([0-9.]+)',
                           insloc:port + "/tcp",
                           regPort:port,
                           regProto:"tcp" );

}

exit( 0 );

###############################################################################
# OpenVAS Vulnerability Test
#
# Go Programming Language SSH Detection
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (C) 2016 SCHUTZWERK GmbH, https://www.schutzwerk.com
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.111089");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2020-08-24T08:40:10+0000");
  script_tag(name:"last_modification", value:"2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2016-03-17 07:42:39 +0100 (Thu, 17 Mar 2016)");
  script_name("Go Programming Language SSH Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 SCHUTZWERK GmbH");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/golang/ssh/detected");

  script_tag(name:"summary", value:"The script sends a connection
  request to the server and attempts to extract the version number
  from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("ssh_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ssh_get_port( default:22 );
banner = ssh_get_serverbanner( port:port );
if( ! banner || "SSH-2.0-Go" >!< banner )
  exit( 0 );

version = "unknown";
cpe = "cpe:/a:golang:go";
install = port + "/tcp";

set_kb_item( name:"go_ssh/detected", value:TRUE );

register_product( cpe:cpe, location:install, port:port, service:"ssh" );

log_message( data:build_detection_report( app:"Go Programming Language SSH",
                                          version:version,
                                          install:install,
                                          cpe:cpe,
                                          concluded:banner ),
                                          port:port );

exit( 0 );

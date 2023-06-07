###################################################################
# OpenVAS Vulnerability Test
#
# FTP Service Allows Any Username
#
# Authors:
# H D Moore
#
# Copyright:
# Copyright (C) 2005 Digital Defense Inc.
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
###################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10990");
  script_version("2021-03-19T08:52:49+0000");
  script_tag(name:"last_modification", value:"2021-03-19 08:52:49 +0000 (Fri, 19 Mar 2021)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("FTP Service Allows Any Username");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Digital Defense Inc.");
  script_family("Service detection");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/banner/available");

  script_tag(name:"summary", value:"The FTP service can be accessed using any username and password.

  Many other FTP plugins may trigger falsely because of this, so the scanner enable some countermeasures.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ftp_get_port( default:21 );

if( ! ftp_get_banner( port:port ) )
  exit( 0 );

if( ftp_broken_random_login( port:port ) )
  log_message( port:port );

exit( 0 );

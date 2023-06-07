###############################################################################
# OpenVAS Vulnerability Test
#
# WU-FTPD Detection
#
# Authors:
# Thorsten Passfeld <thorsten.passfeld@greenbone.net>
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.108437");
  script_version("2020-08-24T08:40:10+0000");
  script_tag(name:"last_modification", value:"2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-04-11 17:09:43 +0200 (Wed, 11 Apr 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("WU-FTPD Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/wu_ftpd/detected");

  script_xref(name:"URL", value:"https://en.wikipedia.org/wiki/WU-FTPD");

  script_tag(name:"summary", value:"This script tries to detect an installed WU-FTPD and its version on the remote host.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("host_details.inc");
include("cpe.inc");

port   = ftp_get_port( default:21 );
banner = ftp_get_banner( port:port );

if( ! banner || ! egrep( string:banner, pattern:"FTP server.*[Vv]ersion (wu|wuftpd)-" ) )
  exit( 0 );

version = "unknown";
install = port + "/tcp";

# 220 $hostname FTP server (Revision 10.0 Version wuftpd-2.6.1 Tue Nov 24 18:59:37 GMT 2015) ready.
# 220 $hostname FTP server (Revision 5.0 Version wuftpd-2.6.1 Thu Apr 29 06:48:40 GMT 2010) ready.
# 220 $hostname FTP server (Version wu-2.6.3(1) Wed Mar 30 15:01:08 CEST 2005) ready.
# 220 $hostname FTP server (Version wu-2.6.2d(1) Thu Nov 10 14:38:49 JST 2005) ready.
vers = eregmatch( string:banner, pattern:"[Vv]ersion (wu|wuftpd)-([0-9.a-z]+)" );
if( vers ) version = vers[2];

set_kb_item( name:"ftp/" + port + "/wu-ftpd", value:version );
set_kb_item( name:"wu-ftpd/installed", value:TRUE );

register_and_report_cpe( app:"WU-FTPD", ver:version, concluded:banner, base:"cpe:/a:washington_university:wu-ftpd:", expr:"([0-9.a-z]+)", insloc:install, regPort:port, regService:"ftp" );

exit( 0 );

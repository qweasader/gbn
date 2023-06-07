###############################################################################
# OpenVAS Vulnerability Test
#
# SSL/TLS: Perfect Forward Secrecy Cipher Suites Missing
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105092");
  script_version("2022-05-31T13:45:57+0100");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"last_modification", value:"2022-05-31 13:45:57 +0100 (Tue, 31 May 2022)");
  script_tag(name:"creation_date", value:"2014-09-23 14:16:10 +0100 (Tue, 23 Sep 2014)");
  script_name("SSL/TLS: Perfect Forward Secrecy Cipher Suites Missing");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_ssl_ciphers_pfs_supported.nasl");
  script_mandatory_keys("SSL/PFS/no_ciphers");

  script_tag(name:"summary", value:"The remote service is missing support for SSL/TLS cipher suites supporting Perfect Forward Secrecy.");

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

port = get_kb_item( "SSL/PFS/no_ciphers/port" );
if( ! port ) exit( 0 );

log_message( port:port, data:"The remote service does not support perfect forward secrecy cipher suites." );
exit( 0 );

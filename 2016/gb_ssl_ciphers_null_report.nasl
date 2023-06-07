# Copyright (C) 2016 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108022");
  script_version("2021-12-01T09:24:41+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-12-01 09:24:41 +0000 (Wed, 01 Dec 2021)");
  script_tag(name:"creation_date", value:"2016-11-24 10:08:04 +0100 (Thu, 24 Nov 2016)");
  script_name("SSL/TLS: Report 'Null' Cipher Suites");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("secpod_ssl_ciphers.nasl");
  script_mandatory_keys("secpod_ssl_ciphers/null_ciphers", "ssl_tls/port");

  script_xref(name:"URL", value:"https://bettercrypto.org/");
  script_xref(name:"URL", value:"https://mozilla.github.io/server-side-tls/ssl-config-generator/");

  script_tag(name:"summary", value:"This routine reports all 'Null' SSL/TLS cipher suites accepted
  by a service.");

  script_tag(name:"insight", value:"Services supporting 'Null' cipher suites could allow a client
  to negotiate an SSL/TLS connection to the host without any encryption of the transferred data.");

  script_tag(name:"impact", value:"This could allow remote attackers to obtain sensitive
  information or have other, unspecified impacts.");

  script_tag(name:"solution", value:"The configuration of this services should be changed so that
  it does not accept the listed 'Null' cipher suites anymore.

  Please see the references for more resources supporting you in this task.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("ssl_funcs.inc");
include("gb_print_ciphers.inc");

if( ! port = tls_ssl_get_port() )
  exit( 0 );

report = print_cipherlists( port:port, strengths:"null" );

if( report ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108147");
  script_version("2022-04-13T11:57:07+0000");
  script_cve_id("CVE-2007-1858", "CVE-2014-0351");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"creation_date", value:"2017-04-20 06:08:04 +0200 (Thu, 20 Apr 2017)");
  script_name("SSL/TLS: Report 'Anonymous' Cipher Suites");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("secpod_ssl_ciphers.nasl");
  script_mandatory_keys("secpod_ssl_ciphers/anon_ciphers", "ssl_tls/port");

  script_xref(name:"URL", value:"https://bettercrypto.org/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/28482");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69754");
  script_xref(name:"URL", value:"https://mozilla.github.io/server-side-tls/ssl-config-generator/");

  script_tag(name:"summary", value:"This routine reports all 'Anonymous' SSL/TLS cipher suites
  accepted by a service.");

  script_tag(name:"insight", value:"Services supporting 'Anonymous' cipher suites could allow a
  client to negotiate an SSL/TLS connection to the host without any authentication of the remote
  endpoint.");

  script_tag(name:"impact", value:"This could allow remote attackers to obtain sensitive
  information or have other, unspecified impacts.");

  script_tag(name:"solution", value:"The configuration of this services should be changed so
  that it does not accept the listed 'Anonymous' cipher suites anymore.

  Please see the references for more resources supporting you in this task.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("ssl_funcs.inc");
include("gb_print_ciphers.inc");

if( ! port = tls_ssl_get_port() )
  exit( 0 );

# Don't report for StartTLS services. A MitM attacker might be already in the position to
# intercept the initial request for StartTLS and force a fallback to plaintext. This avoids
# also that we're reporting this cipher suites on 'Opportunistic TLS' services like SMTP.
if( get_kb_item( "starttls_typ/" + port ) )
  exit( 0 );

report = print_cipherlists( port:port, strengths:"anon" );

if( report ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

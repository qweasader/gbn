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
  script_oid("1.3.6.1.4.1.25623.1.0.105781");
  script_version("2022-07-26T10:10:42+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-07-26 10:10:42 +0000 (Tue, 26 Jul 2022)");
  script_tag(name:"creation_date", value:"2016-06-28 15:37:57 +0200 (Tue, 28 Jun 2016)");
  script_name("SSL/TLS: Policy Check OK");
  script_category(ACT_GATHER_INFO);
  script_family("Policy");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("Policy/gb_policy_tls.nasl", "gb_tls_version_get.nasl");
  script_mandatory_keys("tls_policy/perform_test", "tls_policy/report_passed_tests", "ssl_tls/port");

  script_tag(name:"summary", value:"Shows all supported SSL/TLS versions.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ssl_funcs.inc");

if( ! port = tls_ssl_get_port() )
  exit( 0 );

if( ! passed = get_kb_item( "tls_policy/test_passed/" + port ) )
  exit( 0 );

minimum_TLS = get_kb_item( "tls_policy/minimum_TLS" );

supported_versions = get_kb_list( "tls_version_get/" + port + "/version" );

report  = 'Minimum allowed SSL/TLS version: ' + minimum_TLS + '\n\n';
report += 'The following SSL/TLS versions are supported by the remote service:\n\n';

foreach sv( sort( supported_versions ) )
  report += sv + '\n';

report += '\nSSL/TLS policy test passed.';

log_message( port:port, data:report );
exit( 0 );

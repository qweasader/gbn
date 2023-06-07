###############################################################################
# OpenVAS Vulnerability Test
#
# SSL/TLS: Cert Issuer Policy Check Failed
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.140040");
  script_version("2020-03-31T06:57:15+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-03-31 06:57:15 +0000 (Tue, 31 Mar 2020)");
  script_tag(name:"creation_date", value:"2016-11-01 10:15:30 +0100 (Tue, 01 Nov 2016)");
  script_name("SSL/TLS: Cert Issuer Policy Check Failed");
  script_category(ACT_GATHER_INFO);
  script_family("Policy");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("Policy/gb_policy_cert_issuer.nasl");
  script_mandatory_keys("ssl_tls/port", "policy_cert_issuer/check_issuer", "policy_cert_issuer/run_test");

  script_tag(name:"summary", value:"This script reports if the SSL/TLS certificate is not signed by the given issuer.");

  script_tag(name:"solution", value:"Update or reconfigure the affected service / system / host according to the
  policy requirement.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("ssl_funcs.inc");

if( ! port = tls_ssl_get_port() )
  exit( 0 );

if( ! failed = get_kb_item( "policy_cert_issuer/" + port + "/failed" ) )
  exit( 0 );

issuer = get_kb_item( "policy_cert_issuer/" + port + "/issuer" );
check_issuer = get_kb_item( "policy_cert_issuer/check_issuer" );

report = 'The issuer `' + issuer + '` is not matching the given issuer `' + check_issuer  + '`.';

security_message( port:port, data:report );

exit( 0 );

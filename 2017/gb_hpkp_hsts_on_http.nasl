###############################################################################
# OpenVAS Vulnerability Test
#
# SSL/TLS: HPKP / HSTS / Expect-CT Headers sent via plain HTTP
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.108248");
  script_version("2020-08-28T07:42:46+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-08-28 07:42:46 +0000 (Fri, 28 Aug 2020)");
  script_tag(name:"creation_date", value:"2017-10-09 08:07:41 +0200 (Mon, 09 Oct 2017)");
  script_name("SSL/TLS: HPKP / HSTS / Expect-CT Headers sent via plain HTTP");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  # nb: Don't add a dependency to e.g. webmirror.nasl or DDI_Directory_Scanner.nasl
  # to allow a minimal SSL/TLS check configuration.
  script_dependencies("find_service.nasl", "httpver.nasl");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"https://owasp.org/www-project-cheat-sheets/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html");
  script_xref(name:"URL", value:"https://owasp.org/www-project-secure-headers/");
  script_xref(name:"URL", value:"https://owasp.org/www-project-secure-headers/#public-key-pinning-extension-for-http-hpkp");
  script_xref(name:"URL", value:"https://owasp.org/www-project-secure-headers/#http-strict-transport-security-hsts");
  script_xref(name:"URL", value:"https://owasp.org/www-project-secure-headers/#expect-ct");
  script_xref(name:"URL", value:"https://tools.ietf.org/html/rfc6797");
  script_xref(name:"URL", value:"https://tools.ietf.org/html/rfc7469");
  script_xref(name:"URL", value:"https://securityheaders.io/");
  script_xref(name:"URL", value:"http://httpwg.org/http-extensions/expect-ct.html#http-request-type");

  script_tag(name:"summary", value:"This script checks if the remote HTTP server is sending a HPKP, HSTS
  and/or Expect-CT header via plain HTTP.

  Note: Most major browsers have dropped / deprecated support for this header in 2020.");

  script_tag(name:"solution", value:"Configure the remote host to only send HPKP, HSTS and Expect-CT headers
  via HTTPS. Sending those headers via plain HTTP doesn't comply with the referenced RFCs.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port( default:80, ignore_cgi_disabled:TRUE );
if( get_port_transport( port ) > ENCAPS_IP )
  exit( 0 );

banner = http_get_remote_headers( port:port );
if( ! banner )
  exit( 0 );

if( pkp = egrep( pattern:"^Public-Key-Pins(\-Report\-Only)?\s*:", string:banner, icase:TRUE ) )
  hpkp_on_http = TRUE;

if( sts = egrep( pattern:"^Strict-Transport-Security\s*:", string:banner, icase:TRUE ) )
  hsts_on_http = TRUE;

if( ect = egrep( pattern:"^Expect-CT\s*:", string:banner, icase:TRUE ) )
  ect_on_http = TRUE;

if( hpkp_on_http || hsts_on_http || ect_on_http ) {

  report = 'The remote HTTP server is sending HPKP, HSTS and/or Expect-CT headers via plain HTTP.\n';

  if( hpkp_on_http ) report += '\nHPKP-Header:\n\n' + pkp;
  if( hsts_on_http ) report += '\nHSTS-Header:\n\n' + sts;
  if( ect_on_http )  report += '\nECT-Header:\n\n' + ect;

  log_message( port:port, data:report );
}

exit( 0 );

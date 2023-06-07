# Copyright (C) 2014 SCHUTZWERK GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105925");
  script_version("2023-01-11T10:12:37+0000");
  script_tag(name:"last_modification", value:"2023-01-11 10:12:37 +0000 (Wed, 11 Jan 2023)");
  script_tag(name:"creation_date", value:"2014-09-01 16:00:00 +0100 (Mon, 01 Sep 2014)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Missing 'HttpOnly' Cookie Attribute (HTTP)");
  script_copyright("Copyright (C) 2014 SCHUTZWERK GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.rfc-editor.org/rfc/rfc6265#section-5.2.6");
  script_xref(name:"URL", value:"https://owasp.org/www-community/HttpOnly");
  script_xref(name:"URL", value:"https://wiki.owasp.org/index.php/Testing_for_cookies_attributes_(OTG-SESS-002)");

  script_tag(name:"summary", value:"The remote HTTP web server / application is missing to set the
  'HttpOnly' cookie attribute for one or more sent HTTP cookie.");

  script_tag(name:"vuldetect", value:"Checks all cookies sent by the remote HTTP web server /
  application for a missing 'HttpOnly' cookie attribute.");

  script_tag(name:"insight", value:"The flaw exists if a session cookie is not using the 'HttpOnly'
  cookie attribute.

  This allows a cookie to be accessed by JavaScript which could lead to session hijacking
  attacks.");

  script_tag(name:"affected", value:"Any web application with session handling in cookies.");

  script_tag(name:"solution", value:"Set the 'HttpOnly' attribute for any session cookie.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

buf = http_get_cache( item:"/", port:port );

if( buf && "Set-Cookie:" >< buf ) {

  cookies = egrep( string:buf, pattern:"Set-Cookie:.*" );

  if( cookies ) {

    cookiesList = split( cookies, sep:'\n', keep:FALSE );
    vuln = FALSE;

    foreach cookie( cookiesList ) {

      if( cookie !~ ";[ ]?[H|h]ttp[O|o]nly?[^a-zA-Z0-9_-]?" ) {
        # Clean-up cookies from dynamic data so we don't report differences on the delta report
        pattern = "(Set-Cookie:.*=)([a-zA-Z0-9]+)(;.*)";
        if( eregmatch( pattern:pattern, string:cookie ) ) {
          cookie = ereg_replace( string:cookie, pattern:pattern, replace:"\1***replaced***\3" );
        }
        vuln = TRUE;
        vulnCookies += cookie + '\n';
      }
    }

    if( vuln ) {
      report = 'The cookies:\n\n' + vulnCookies + '\nare missing the "HttpOnly" attribute.';
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );

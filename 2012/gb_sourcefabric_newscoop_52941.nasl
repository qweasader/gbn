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
  script_oid("1.3.6.1.4.1.25623.1.0.103461");
  script_version("2023-01-23T10:11:56+0000");
  script_tag(name:"last_modification", value:"2023-01-23 10:11:56 +0000 (Mon, 23 Jan 2023)");
  script_tag(name:"creation_date", value:"2012-04-10 10:02:36 +0200 (Tue, 10 Apr 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2012-1934");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Sourcefabric Newscoop <= 3.5.4 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Sourcefabric Newscoop is prone to multiple cross-site scripting
  (XSS) and SQL injection (SQLi) vulnerabilities because it fails to properly sanitize
  user-supplied input before using it in dynamically generated content.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Exploiting these issues could allow an attacker to steal
  cookie-based authentication credentials, compromise the application, access or modify data, or
  exploit latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"Sourcefabric Newscoop version 3.5.4 and probably prior.");

  script_tag(name:"solution", value:"Please see the references for a solution.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52941");
  script_xref(name:"URL", value:"http://dev.sourcefabric.org/browse/CS-4184");
  script_xref(name:"URL", value:"http://dev.sourcefabric.org/browse/CS-4183");
  script_xref(name:"URL", value:"http://dev.sourcefabric.org/browse/CS-4182");
  script_xref(name:"URL", value:"http://www.sourcefabric.org/en/products/newscoop_release/570/Newscoop-352-is-out!.htm");
  script_xref(name:"URL", value:"http://dev.sourcefabric.org/browse/CS-4181");
  script_xref(name:"URL", value:"http://www.sourcefabric.org/en/newscoop/latestrelease/1141/Newscoop-355-and-Newscoop-4-RC4-security-releases.htm");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

if( ! http_can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/newscoop", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  url = dir + "/admin/password_check_token.php";
  res = http_get_cache( port:port, item:url );

  if( ! res || res !~ "^HTTP/1\.[01] 200" )
    continue;

  url = dir + "/admin/password_check_token.php?f_email=1&token=%22%3E%3Cscript%3Ealert%28/xss-test/%29;%3C/script%3E";

  if( http_vuln_check( port:port, url:url, pattern:"<script>alert\(/xss-test/\);</script>", check_header:TRUE,
                       extra_check:"Bad input parameters" ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

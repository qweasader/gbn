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
  script_oid("1.3.6.1.4.1.25623.1.0.902840");
  script_version("2022-04-27T12:01:52+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-05-28 15:15:15 +0530 (Mon, 28 May 2012)");
  script_name("Adiscon LogAnalyzer Multiple SQL Injection and XSS Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/49223");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53664");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/113037/CSA-12005.txt");
  script_xref(name:"URL", value:"http://www.codseq.it/advisories/multiple_vulnerabilities_in_loganalyzer");
  script_xref(name:"URL", value:"http://loganalyzer.adiscon.com/news/loganalyzer-v3-4-3-v3-stable-released");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to steal cookie based
  authentication credentials, compromise the application, access or modify
  data or  exploit latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"Adiscon LogAnalyzer version 3.4.2 and prior");

  script_tag(name:"insight", value:"Multiple flaws are due to

  - Input passed via the 'filter' parameter to index.php, the 'id' parameter to
    admin/reports.php and admin/searches.php is not properly sanitised before
    being returned to the user.

  - Input passed via the 'Columns[]' parameter to admin/views.php is not
    properly sanitised before being used in SQL queries.");

  script_tag(name:"solution", value:"Upgrade to Adiscon LogAnalyzer version 3.4.3 or later.");

  script_tag(name:"summary", value:"Adiscon LogAnalyzer is prone to multiple SQL injection and cross site scripting vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port))
  exit(0);

foreach dir (make_list_unique("/loganalyzer", "/log", http_cgi_dirs(port:port)))
{
  if(dir == "/") dir = "";
  url = dir + "/index.php";
  res = http_get_cache( item:url, port:port );
  if( isnull( res ) ) continue;

  if( res =~ "^HTTP/1\.[01] 200" && ">Adiscon LogAnalyzer<" >< res ) {

    url += "?filter=</title><script>alert(document.cookie)</script>";

    if(http_vuln_check( port: port, url: url, check_header: TRUE,
                        pattern: "<script>alert\(document\.cookie\)</script>",
                        extra_check: ">Adiscon LogAnalyzer<"))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);

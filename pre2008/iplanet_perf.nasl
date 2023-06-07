# OpenVAS Vulnerability Test
# Description: Netscape /.perf accessible
#
# Authors:
# Sullo (sullo@cirt.net)
#
# Copyright:
# Copyright (C) 2003 Sullo
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

CPE = "cpe:/a:netscape:server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11220");
  script_version("2022-12-05T10:11:03+0000");
  script_tag(name:"last_modification", value:"2022-12-05 10:11:03 +0000 (Mon, 05 Dec 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Netscape /.perf accessible");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2003 Sullo");
  script_family("Web Servers");
  script_dependencies("gb_netscape_server_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("netscape/server/detected");

  script_tag(name:"solution", value:"If you don't use this feature, server monitoring should be
  disabled in the magnus.conf file or web server admin.");

  script_tag(name:"summary", value:"Requesting the URI /.perf gives information about
  the currently running Netscape/iPlanet web server.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

url = "/.perf";
req = http_get(item:url, port:port);
res = http_send_recv(port:port, data:req);
if(!res)
  exit(0);

if("ListenSocket" >< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

# OpenVAS Vulnerability Test
# Description: Oracle XSQLServlet XSQLConfig.xml File
#
# Authors:
# Matt Moore <matt.moore@westpoint.ltd.uk>
#
# Copyright:
# Copyright (C) 2002 Matt Moore
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

CPE = "cpe:/a:oracle:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10855");
  script_version("2022-12-05T10:11:03+0000");
  script_tag(name:"last_modification", value:"2022-12-05 10:11:03 +0000 (Mon, 05 Dec 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2002-0568");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Oracle XSQLServlet XSQLConfig.xml File");

  script_xref(name:"URL", value:"http://www.nextgenss.com/papers/hpoas.pdf");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4290");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_active");

  script_copyright("Copyright (C) 2002 Matt Moore");
  script_family("Web application abuses");
  script_dependencies("gb_oracle_app_server_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("oracle/http_server/detected");

  script_tag(name:"solution_type", value:"Workaround");

  script_tag(name:"solution", value:"Move this file to a safer location and update your servlet engine's
  configuration file to reflect the change.");

  script_tag(name:"summary", value:"It is possible to read the contents of the XSQLConfig.xml file which contains
  sensitive information.");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

req = http_get(item:"/xsql/lib/XSQLConfig.xml",
               port:port);

soc = http_open_socket(port);
if(!soc)
  exit(0);

send(socket:soc, data:req);
r = http_recv(socket:soc);
tip = string("On a PRODUCTION system, under no circumstances should this configuration file reside in a directory that is browsable through the virtual path of your web server.");

if(tip >< r) {
  http_close_socket(soc);
  security_message(port);
} else {
  req = http_get(item:"/servlet/oracle.xml.xsql.XSQLServlet/xsql/lib/XSQLConfig.xml", port:port);
  soc = http_open_socket(port);
  if(soc) {
    send(socket:soc, data:req);
    r = http_recv(socket:soc);
    http_close_socket(soc);
    if(tip >< r)
      security_message(port);
  }
}

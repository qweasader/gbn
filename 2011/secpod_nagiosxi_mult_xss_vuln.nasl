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
  script_oid("1.3.6.1.4.1.25623.1.0.902599");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-12-16 10:10:10 +0530 (Fri, 16 Dec 2011)");
  script_name("Nagios XI Multiple Cross Site Scripting Vulnerabilities");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51069");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/71825");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/71826");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2011/Dec/354");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/107872/0A29-11-3.txt");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_nagios_XI_detect.nasl");
  script_mandatory_keys("nagiosxi/installed");
  script_require_ports("Services/www", 80);
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.");
  script_tag(name:"affected", value:"Nagios XI versions prior to 2011R1.9");
  script_tag(name:"insight", value:"Multiple flaws are due to improper validation of user-supplied input
  appended to the URL in multiple scripts, which allows attackers to execute
  arbitrary HTML and script code in a user's browser session in the context
  of an affected site.");
  script_tag(name:"solution", value:"Upgrade to Nagios XI version 2011R1.9 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Nagios XI is prone to multiple cross-site scripting vulnerabilities.");
  script_xref(name:"URL", value:"http://www.nagios.com/products/nagiosxi");
  exit(0);
}

CPE = "cpe:/a:nagios:nagiosxi";

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!dir = get_app_location(cpe:CPE, port:port)) exit(0);

if(dir == "/") dir = "";

url = dir + '/login.php/";alert(document.cookie);"';

if(http_vuln_check(port:port, url:url, check_header: TRUE,
   pattern:";alert\(document.cookie\);")) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

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

CPE = "cpe:/a:adobe:coldfusion";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902576");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-09-30 15:58:03 +0200 (Fri, 30 Sep 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Adobe ColdFusion Multiple Cross Site Scripting Vulnerabilities");
  script_xref(name:"URL", value:"http://websecurity.com.ua/5243/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49787");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2011/Sep/285");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/105344/coldfusion-xssdisclose.txt");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_coldfusion_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("adobe/coldfusion/http/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to insert arbitrary
  HTML and script code, which will be executed in a user's browser session in
  the context of an affected site.");

  script_tag(name:"affected", value:"Adobe ColdFusion version 7.");

  script_tag(name:"insight", value:"Multiple flaws are caused by improper validation of user-supplied
  input passed via the 'component' parameter in componentdetail.cfm, 'method'
  parameter in cfcexplorer.cfc and header 'User-Agent' in cfcexplorer.cfc,
  probe.cfm, Application.cfm, _component_cfcToHTML.cfm and
  _component_cfcToMCDL.cfm, that allows attackers to execute arbitrary HTML
  and script code on the web server.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Adobe ColdFusion is prone to multiple cross site scripting vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(port:port, cpe:CPE, nofork:TRUE))
  exit(0);

host = http_host_name(port:port);

url = "/CFIDE/probe.cfm";
req = string("GET ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: <script>alert(document.cookie)</script>\r\n\r\n");

res = http_send_recv(port:port, data:req);

if(ereg(pattern:"^HTTP/1\.[01] 200", string:res) &&
  ('><script>alert(document.cookie)</script>' >< res)) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
###############################################################################
# OpenVAS Vulnerability Test
#
# Brother MFC Administration Reflected Cross-Site Scripting Vulnerabilities - Jan15
#
# Authors:
# Deependra Bapna <bdeependra@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805320");
  script_version("2021-10-21T13:57:32+0000");
  script_cve_id("CVE-2015-1056");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-10-21 13:57:32 +0000 (Thu, 21 Oct 2021)");
  script_tag(name:"creation_date", value:"2015-01-12 20:15:26 +0530 (Mon, 12 Jan 2015)");
  script_name("Brother MFC Administration Reflected Cross-Site Scripting Vulnerabilities - Jan15");

  script_tag(name:"summary", value:"MFC-J4410DW model printer firmware is prone to cross-site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Flaw is due to improper validation of
  'url' parameter in 'status.html' page before being returned to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary HTML and script code in a users browser
  session in the context of an affected site.");

  script_tag(name:"affected", value:"Brother MFC-J4410DW with F/W Versions J and K");

  script_tag(name:"solution", value:"Upgrade to latest firmware version.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2015/Jan/19");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

cmsPort = http_get_port(default:80);

url = "/general/status.html";
req = http_get(item:url, port:cmsPort);
res = http_send_recv(port:cmsPort, data:req);

if(res && ">Brother MFC-J4410DW series<" >< res)
{
  url += '?url="/><script>alert(document.cookie)</script><input type="hidden" value="';
  if(http_vuln_check(port:cmsPort, url:url, check_header:TRUE,
    pattern:"<script>alert\(document.cookie\)</script>"))
  {
    report = http_report_vuln_url( port:cmsPort, url:url );
    security_message(port:cmsPort, data:report);
    exit(0);
  }
}

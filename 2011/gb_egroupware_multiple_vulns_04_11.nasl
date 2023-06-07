###############################################################################
# OpenVAS Vulnerability Test
#
# eGroupware <= 1.8.001 Multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
CPE = "cpe:/a:egroupware:egroupware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103151");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-04-29 15:04:36 +0200 (Fri, 29 Apr 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("eGroupware <= 1.8.001 Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47273");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47262");
  script_xref(name:"URL", value:"http://www.egroupware.org/");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_egroupware_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("egroupware/installed");
  script_tag(name:"summary", value:"eGroupware is prone to a cross-site scripting vulnerability and to a
SQL-injection vulnerability because it fails to sufficiently sanitize
user-supplied data.

An attacker may leverage the  cross-site scripting issue to execute arbitrary
script code in the browser of an unsuspecting user in the context of the affected
site. This may allow the attacker to steal cookie-based authentication
credentials and to launch other attacks.

Exploiting the SQL-injection issue could allow an attacker to compromise the
application, access or modify data, or exploit latent vulnerabilities
in the underlying database.

eGroupware 1.8.001 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(!dir = get_app_location(cpe:CPE, port:port))exit(0);

vt_strings = get_vt_strings();

url = string(dir,'/phpgwapi/js/jscalendar/test.php?lang="></script><script>alert(/', vt_strings["lowercase"], '/)</script>');

if(http_vuln_check(port:port,url:url,pattern:"<script>alert\(/" + vt_strings["lowercase"] + "/\)</script>",check_header:TRUE,extra_check:make_list("Calendar.php ","Test for calendar.php"))) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);

}

exit(0);

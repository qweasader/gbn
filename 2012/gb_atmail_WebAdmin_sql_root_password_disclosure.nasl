###############################################################################
# OpenVAS Vulnerability Test
#
# Atmail WebAdmin and Webmail Control Panel SQL Root Password Disclosure
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH
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

CPE = "cpe:/a:atmail:atmail";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103524");
  script_version("2022-04-27T12:01:52+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Atmail WebAdmin and Webmail Control Panel SQL Root Password Disclosure");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54641");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/114955/Atmail-WebAdmin-Webmail-Control-Panel-SQL-Root-Password-Disclosure.html");

  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-07-24 11:10:51 +0200 (Tue, 24 Jul 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("atmail_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Atmail/installed");

  script_tag(name:"summary", value:"Atmail WebAdmin and Webmail Control Panel suffers from a SQL root password disclosure vulnerability.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!dir = get_app_location(cpe:CPE, port:port)) exit(0);

if (dir == "/")
  dir = "";

url = dir + '/config/dbconfig.ini';

if (http_vuln_check(port:port, url:url, pattern:"database.adapter",
                    extra_check:make_list("database.params.host","database.params.username","database.params.password"))) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port:port, data: report);
  exit(0);
}

exit(0);


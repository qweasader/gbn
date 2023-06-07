# OpenVAS Vulnerability Test
# Description: Apache Auth Module SQL Insertion Attack
#
# Authors:
# 2001 Matt Moore <matt@westpoint.ltd.uk>
# modifications by rd : use of regexps
#
# Copyright:
# Copyright (C) 2001 Matt Moore
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

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10752");
  script_version("2022-12-05T10:11:03+0000");
  script_tag(name:"last_modification", value:"2022-12-05 10:11:03 +0000 (Mon, 05 Dec 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3251");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3253");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2001-1379");

  script_name("Apache HTTP Server Auth Module SQL Insertion Attack");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");

  script_copyright("Copyright (C) 2001 Matt Moore");
  script_family("Web Servers");

  script_dependencies("gb_apache_http_server_consolidation.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("apache/http_server/http/detected");

  script_tag(name:"solution", value:"Update the module.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"This plugin checks whether the web server is
  using Apache Auth modules which are known to be vulnerable to SQL
  insertion attacks.");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

banner = http_get_remote_headers(port:port);

report =
string("There is a vulnerable version of the NAME module installed on this\n",
"Apache Web Server.\n",
"This module is vulnerable to a SQL insertion attack that could allow an\n",
"attacker to execute arbitrary SQL statements.\n\n",
"Solution: Get the latest version of this module (probably VERSION) at URL\n\n",
"References: RUS CERT Advisory available at http://cert-uni-stuttgart.de/advisories/apache_auth.php");

# Now check whether the banner contains references to the vulnerable modules...

if(egrep(pattern:"^Server:.*mod_auth_pg/((0\.[0-9])|(1\.[01])|1\.2b[0-2])([^0-9]|$)", string:banner)) {
  r = ereg_replace(pattern:"(.*)(NAME)(.*)(VERSION)(.*)(URL)(.*)", replace:"\1mod_auth_pg\31.3\5http://authpg.sourceforge.net\7", string:report);
  security_message(port:port, data:r);
  exit(0);
}


if(egrep(pattern:"^Server:.*mod_auth_mysql/((0\.[0-9])|(1\.[0-9]))([^0-9]|$)", string:banner)) {
  r = ereg_replace(pattern:"(.*)(NAME)(.*)(VERSION)(.*)(URL)(.*)", replace:"\1mod_auth_mysql\31.10\5ftp://ftp.kcilink.com/pub/\7", string:report);
  security_message(port:port, data:r);
  exit(0);
}

if(egrep(pattern:"^Server:.*mod_auth_oracle/0\.([0-4].*|5\.[01]([^0-9]|$))", string:banner)) {
  r = ereg_replace(pattern:"(.*)(NAME)(.*)(VERSION)(.*)(URL)(.*)", replace:"\1mod_auth_oracle\30.5.2\5some place\7", string:report);
  security_message(port:port, data:r);
  exit(0);
}

if(egrep(pattern:"^Server:.*mod_auth_pgsql/0\.(([0-8]\..*)|(9\.[0-5]([^0-9]|$))).*", string:banner)) {
  r = ereg_replace(pattern:"(.*)(NAME)(.*)(VERSION)(.*)(URL)(.*)", replace:"\1mod_auth_pgsql\30.9.6\5http://www.giuseppetanzilli.it/mod_auth_pgsql/dist\7", string:report);
  security_message(port:port, data:r);
  exit(0);
}


if(egrep(pattern:"^Server:.*mod_auth_pgsql_sys/0\.(([0-8]\..*)|(9\.[0-4]([^0-9]|$))).*", string:banner)) {
  r = ereg_replace(pattern:"(.*)(NAME)(.*)(VERSION)(.*)(URL)(.*)", replace:"\1mod_auth_pgsql_sys\30.9.5\5some place\7", string:report);
  security_message(port:port, data:r);
  exit(0);
}

exit(99);

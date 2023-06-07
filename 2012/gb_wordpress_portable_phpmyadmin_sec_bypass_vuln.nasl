###############################################################################
# OpenVAS Vulnerability Test
#
# WordPress Portable phpMyAdmin Plugin 'wp-pma-mod' Security Bypass Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803077");
  script_version("2023-03-01T10:20:04+0000");
  script_cve_id("CVE-2012-5469");
  script_tag(name:"last_modification", value:"2023-03-01 10:20:04 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"creation_date", value:"2012-12-17 17:58:04 +0530 (Mon, 17 Dec 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("WordPress Portable phpMyAdmin Plugin 'wp-pma-mod' Security Bypass Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/51520/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56920");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/80654");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2012/Dec/91");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/23356/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/118805/WordPress-portable-phpMyAdmin-1.3.0-Authentication-Bypass.html");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to gain sensitive
  information.");

  script_tag(name:"affected", value:"WordPress Portable phpMyAdmin plugin version 1.3.0");

  script_tag(name:"insight", value:"The plugin fails to verify an existing WordPress session when accessing the
  plugin file path directly. An attacker can get a full phpMyAdmin console
  with the privilege level of the MySQL configuration of WordPress by
  accessing 'wp-content/plugins/portable-phpmyadmin/wp-pma-mod'.");

  script_tag(name:"solution", value:"Update to the WordPress Portable phpMyAdmin Plugin 1.3.1 or later.");

  script_tag(name:"summary", value:"WordPress Portable phpMyAdmin Plugin is prone to a security bypass vulnerability.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/portable-phpmyadmin/");
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

url = dir + '/wp-content/plugins/portable-phpmyadmin/wp-pma-mod/';

if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:"<title>phpMyAdmin", extra_check:make_list('db_structure.php', 'server', 'pma_absolute_uri'))){
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

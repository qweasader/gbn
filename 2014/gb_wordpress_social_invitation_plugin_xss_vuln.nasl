###############################################################################
# OpenVAS Vulnerability Test
#
# WordPress Social Invitations Plugin 'test.php' XSS Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804756");
  script_version("2023-03-01T10:20:04+0000");
  script_cve_id("CVE-2014-4597");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-03-01 10:20:04 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"creation_date", value:"2014-08-26 15:58:57 +0530 (Tue, 26 Aug 2014)");
  script_name("WordPress Social Invitations Plugin 'test.php' XSS Vulnerability");

  script_tag(name:"summary", value:"WordPress Social Invitations Plugin is prone to a cross-site scripting (XSS) vulnerability.");
  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able to read
cookie or not.");
  script_tag(name:"insight", value:"Input passed via the 'xhrurl' HTTP GET parameter to test.php script is not
properly sanitised before returning to the user.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
script code in a user's browser session in the context of an affected site.");
  script_tag(name:"affected", value:"WordPress Social Invitations Plugin version before 1.4.4.3");
  script_tag(name:"solution", value:"Update to version 1.4.4.3 or later.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.cnnvd.org.cn/vulnerability/show/cv_id/2014070134");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65268");
  script_xref(name:"URL", value:"http://codevigilant.com/disclosure/wp-plugin-wp-social-invitations-a3-cross-site-scripting-xss");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://wordpress.org/plugins/wp-social-invitations");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/wp-content/plugins/wp-social-invitations/test.php?xhrurl"
          + "=xhrurl'><script>alert(document.cookie)</script>";

## Extra Check is not possible
if(http_vuln_check(port:port, url:url, check_header:TRUE,
   pattern:"<script>alert\(document\.cookie\)</script>"))
{
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}
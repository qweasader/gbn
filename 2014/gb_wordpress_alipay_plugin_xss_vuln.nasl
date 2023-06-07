###############################################################################
# OpenVAS Vulnerability Test
#
# WordPress Alipay plugin Cross Site Scripting Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.804873");
  script_version("2023-03-01T10:20:04+0000");
  script_cve_id("CVE-2014-4514");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-03-01 10:20:04 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"creation_date", value:"2014-10-29 15:09:33 +0530 (Wed, 29 Oct 2014)");
  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Alipay Plugin < 3.6.2 XSS Vulnerability");

  script_tag(name:"summary", value:"The WordPress plugin 'Alipay' is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Input passed via the para_ret['total_fee GET
  parameter to inc.tenpay_notify.php script is not validated before returning it
  to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary HTML and script code in a users browser session
  in the context of an affected site.");

  script_tag(name:"affected", value:"WordPress Alipay plugin 3.6.0 and earlier");

  script_tag(name:"solution", value:"Update to WordPress Alipay plugin 3.6.2
  or later.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/97736");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70695");
  script_xref(name:"URL", value:"http://codevigilant.com/disclosure/wp-plugin-alipay-a3-cross-site-scripting-xss/");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"https://wordpress.org/plugins/alipay/");
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

url = dir + "/wp-content/plugins/alipay/includes/api_tenpay/inc.tenpay_no"
          + "tify.php?$para_ret['total_fee=$para_ret['total_fee'><script>"
          + "alert(document.cookie)</script>";

if(http_vuln_check(port:port, url:url, check_header:TRUE,
  pattern:"<script>alert\(document\.cookie\)</script>",
  extra_check:"tenpay"))
{
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

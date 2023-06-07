###############################################################################
# OpenVAS Vulnerability Test
#
# WordPress NextGen Smooth Gallery Plugin Cross Site Scripting Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.803887");
  script_version("2023-03-01T10:20:04+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-03-01 10:20:04 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"creation_date", value:"2013-09-04 17:41:47 +0530 (Wed, 04 Sep 2013)");
  script_name("WordPress NextGen Smooth Gallery Plugin <= 1.2 XSS Vulnerability");

  script_tag(name:"summary", value:"The WordPress plugin 'NextGen Smooth Gallery' is prone to a cross-site scripting (XSS) vulnerability.");
  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check whether it is able to read the
cookie or not.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.");
  script_tag(name:"insight", value:"Input passed via the 'galleryID' parameter to nggSmoothFrame.php script is
not properly sanitised before being returned to the user.");
  script_tag(name:"affected", value:"WordPress NextGen Smooth Gallery plugin version 1.2 and prior.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
script code in a user's browser session in the context of an affected site.");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://nakedsecurity.com/nsa/181021.htm");
  script_xref(name:"URL", value:"http://cxsecurity.com/issue/WLB-2013090036");
  script_xref(name:"URL", value:"http://dl.packetstormsecurity.net/1309-exploits/wpngsg-xss.txt");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/wordpress-nextgen-smooth-gallery-cross-site-scripting");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);
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

url = dir + '/wp-content/plugins/nextgen-smooth-gallery/nggSmoothFrame.php?'+
                 'galleryID=187"><script>alert(document.cookie)</script>';

if(http_vuln_check(port:port, url:url, check_header:TRUE,
                   pattern:"<script>alert\(document\.cookie\)</script>",
                   extra_check:make_list("myGallery_187", "domready")))
{
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

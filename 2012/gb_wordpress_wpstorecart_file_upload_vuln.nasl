##############################################################################
# OpenVAS Vulnerability Test
#
# WordPress wpStoreCart Plugin 'upload.php' Arbitrary File Upload Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.802915");
  script_version("2023-03-01T10:20:04+0000");
  script_cve_id("CVE-2012-3576");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-03-01 10:20:04 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"creation_date", value:"2012-07-17 15:31:41 +0530 (Tue, 17 Jul 2012)");
  script_name("WordPress wpStoreCart Plugin 'upload.php' Arbitrary File Upload Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/49459");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53896");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/76166");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/19023/");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to upload arbitrary PHP code
  and run it in the context of the Web server process.");
  script_tag(name:"affected", value:"WordPress wpStoreCart Plugin versions 2.5.27 to 2.5.29");
  script_tag(name:"insight", value:"The wp-content/plugins/wpstorecart/php/upload.php script allowing to upload
  files with arbitrary extensions to a folder inside the webroot. This can be
  exploited to execute arbitrary PHP code by uploading a malicious PHP script.");
  script_tag(name:"solution", value:"Update to WordPress wpStoreCart Plugin version 2.5.30 or later.");
  script_tag(name:"summary", value:"WordPress wpStoreCart Plugin is prone to file upload vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/wpstorecart/");
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

url = dir + "/wp-content/plugins/wpstorecart/php/upload.php";

req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req);

## On Non-vuln setup, response will be death 1
if(egrep(pattern:"^HTTP/1\.[01] 200", string:res) &&
   '>alert("No upload found in $_FILES for Filedata' >< res && "death 1" >!< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

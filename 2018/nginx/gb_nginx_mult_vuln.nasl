###############################################################################
# OpenVAS Vulnerability Test
#
# nginx 1.9.5 < 1.14.1, 1.15.x < 1.15.6 Multiple Vulnerabilities
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.112419");
  script_version("2022-04-13T07:21:45+0000");
  script_cve_id("CVE-2018-16843", "CVE-2018-16844");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2022-04-13 07:21:45 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-08 17:50:00 +0000 (Tue, 08 Sep 2020)");
  script_tag(name:"creation_date", value:"2018-11-12 11:41:11 +0100 (Mon, 12 Nov 2018)");

  script_name("nginx 1.9.5 < 1.14.1, 1.15.x < 1.15.6 Multiple Vulnerabilities");

  script_tag(name:"summary", value:"Two security issues were identified in the nginx HTTP/2 implementation,
  which might cause excessive memory consumption and CPU usage.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The issues affect nginx compiled with the ngx_http_v2_module (not
  compiled by default) if the 'http2' option of the 'listen' directive is
  used in a configuration file.");

  script_tag(name:"affected", value:"nginx versions 1.9.5 up to 1.14.0 and 1.15.x up to 1.15.5.");

  script_tag(name:"solution", value:"Update nginx to version 1.14.1 or 1.15.6 respectively.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_xref(name:"URL", value:"http://mailman.nginx.org/pipermail/nginx-announce/2018/000220.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/105868");

  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_dependencies("gb_nginx_consolidation.nasl");
  script_mandatory_keys("nginx/detected");

  exit(0);
}

CPE = "cpe:/a:nginx:nginx";

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe: CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "1.9.5", test_version2: "1.14.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.14.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "1.15.0", test_version2: "1.15.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.15.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );

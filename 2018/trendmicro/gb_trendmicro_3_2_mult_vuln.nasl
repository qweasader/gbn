###############################################################################
# OpenVAS Vulnerability Test
#
# Trend Micro Smart Protection Server <= 3.3 Multiple Vulnerabilities
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113088");
  script_version("2022-04-13T07:21:45+0000");
  script_tag(name:"last_modification", value:"2022-04-13 07:21:45 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"creation_date", value:"2018-01-23 11:11:11 +0100 (Tue, 23 Jan 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:23:00 +0000 (Wed, 09 Oct 2019)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-11398", "CVE-2017-14094", "CVE-2017-14095", "CVE-2017-14096", "CVE-2017-14097");

  script_name("Trend Micro Smart Protection Server <= 3.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_trendmicro_smart_protection_server_detect.nasl");
  script_mandatory_keys("trendmicro/sps/detected");

  script_tag(name:"summary", value:"Trend Micro Smart Protection Server through version 3.2 is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"The script checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Trend Micro Smart Protection Server 3.2 is prone to

  - 3 Remote Code Execution (RCE) vulnerabilities

  - A Session Hijacking Vulnerability

  - An Information Disclosure Vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to access sensitive information or even get
  control of the target host.");

  script_tag(name:"affected", value:"Trend Micro Smart Protection Server version 3.3 and prior.");

  script_tag(name:"solution", value:"Update to version 3.0 CP B1354, 3.1 CP B1057, 3.2 CP B1086, 3.3 B1064 or later.");

  script_xref(name:"URL", value:"https://success.trendmicro.com/solution/1118992");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102275");
  script_xref(name:"URL", value:"https://www.coresecurity.com/advisories/trend-micro-smart-protection-server-multiple-vulnerabilities");

  exit(0);
}

CPE = "cpe:/a:trendmicro:smart_protection_server";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

build = get_kb_item("trendmicro/sps/build");

if( version_is_less_equal( version: version, test_version: "3.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.0 CP B1354", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
} else if( version == "3.1" ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.1 CP B1057", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
} else if( version == "3.2" ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.2 CP B1086", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
} else if( version == "3.3" ) {
  if( !build || version_is_less( version: build, test_version: "1064" ) ) {
    report = report_fixed_ver( installed_version: version, installed_build: build,
                               fixed_version: "3.3", fixed_build: "1064", install_path: location );
    security_message( port: port, data: report );
    exit( 0 );
  }
}

exit( 99 );

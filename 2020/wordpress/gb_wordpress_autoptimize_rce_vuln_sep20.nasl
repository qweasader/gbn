# Copyright (C) 2020 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113753");
  script_version("2022-07-19T10:11:08+0000");
  script_tag(name:"last_modification", value:"2022-07-19 10:11:08 +0000 (Tue, 19 Jul 2022)");
  script_tag(name:"creation_date", value:"2020-09-08 12:01:15 +0000 (Tue, 08 Sep 2020)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-04 20:45:00 +0000 (Thu, 04 Mar 2021)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-24948");

  script_name("WordPress Autoptimize Plugin <= 2.7.6 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/autoptimize/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Autoptimize' is prone
  to a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability exists because the ao_ccss_import AJAX call
  does not ensure that the file provided is a legitimate Zip file,
  allowing high privilege users to upload arbitrary files, such as PHP.");

  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacker
  to execute arbitrary commands on the target machine.");

  script_tag(name:"affected", value:"WordPress Autoptimize plugin through version 2.7.6.");

  script_tag(name:"solution", value:"Update to version 2.7.7.");

  script_xref(name:"URL", value:"https://wpvulndb.com/vulnerabilities/10372");
  script_xref(name:"URL", value:"https://de.wordpress.org/plugins/autoptimize/#developers");

  exit(0);
}

CPE = "cpe:/a:autoptimize:autoptimize";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "2.7.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.7.7", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.112673");
  script_version("2021-09-06T14:01:33+0000");
  script_tag(name:"last_modification", value:"2021-09-06 14:01:33 +0000 (Mon, 06 Sep 2021)");
  script_tag(name:"creation_date", value:"2019-12-09 14:23:50 +0000 (Mon, 09 Dec 2019)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-04 20:55:00 +0000 (Wed, 04 Dec 2019)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-5109", "CVE-2019-5110", "CVE-2019-5111", "CVE-2019-5112");

  script_name("forma.lms <= 2.2.1 Multiple SQL Injection Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_formalms_http_detect.nasl");
  script_mandatory_keys("formalms/detected");

  script_tag(name:"summary", value:"Forma Learning Management System is prone to multiple SQL injection vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple SQL injection vulnerabilities exist in the authenticated portion of Forma LMS 2.2.1.
  Specially crafted web requests can cause SQL injections.");

  script_tag(name:"impact", value:"An attacker can send a web request with parameters containing SQL injection attacks
  to trigger this vulnerability, potentially allowing exfiltration of the database, user credentials and,
  in certain configurations, access the underlying operating system.");

  script_tag(name:"affected", value:"forma.lms through version 2.2.1.");

  script_tag(name:"solution", value:"Update to version 2.3 or later.");

  script_xref(name:"URL", value:"https://talosintelligence.com/vulnerability_reports/TALOS-2019-0902");
  script_xref(name:"URL", value:"https://talosintelligence.com/vulnerability_reports/TALOS-2019-0903");
  script_xref(name:"URL", value:"https://talosintelligence.com/vulnerability_reports/TALOS-2019-0904");

  exit(0);
}

CPE = "cpe:/a:formalms:formalms";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "2.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.3", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

# Copyright (C) 2019 Greenbone Networks GmbH, https://www.greenbone.net
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.112670");
  script_version("2021-08-31T08:01:19+0000");
  script_tag(name:"last_modification", value:"2021-08-31 08:01:19 +0000 (Tue, 31 Aug 2021)");
  script_tag(name:"creation_date", value:"2019-11-22 10:38:11 +0000 (Fri, 22 Nov 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-18887", "CVE-2019-18888");

  script_name("Symfony 2.8.0 <= 2.8.51, 3.4.0 <= 3.4.34, 4.2.0 <= 4.2.11 and 4.3.0 <= 4.3.7 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_symfony_consolidation.nasl");
  script_mandatory_keys("symfony/detected");

  script_tag(name:"summary", value:"Symfony is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - When checking the signature of an URI (an ESI fragment URL for instance),
  the URISigner did not used a constant time string comparison function,
  resulting in a potential remote timing attack vulnerability.

  - Provided file paths were not being properly escaped before being used in
  the FileBinaryMimeTypeGuesser resulting in potential argument injection through the provided $path variable.");

  script_tag(name:"affected", value:"Symfony versions 2.8.0 to 2.8.51, 3.4.0 to 3.4.34, 4.2.0 to 4.2.11 and 4.3.0 to 4.3.7.");

  script_tag(name:"solution", value:"The issue has been fixed in Symfony 2.8.52, 3.4.35, 4.2.12 and 4.3.8.

  NOTE: Note that no fixes are provided for Symfony 3.0, 3.1, 3.2, 3.3, 4.0 and 4.1 as they are not maintained anymore.
  This will be the last Symfony 2.8 security fix as it enters EOL. Please upgrade to a more recent version of Symfony to continue receiving updates.");

  script_xref(name:"URL", value:"https://symfony.com/blog/cve-2019-18887-use-constant-time-comparison-in-urisigner");
  script_xref(name:"URL", value:"https://symfony.com/blog/cve-2019-18888-prevent-argument-injection-in-a-mimetypeguesser");

  exit(0);
}

CPE = "cpe:/a:sensiolabs:symfony";

include( "host_details.inc" );
include( "version_func.inc" );

if( isnull( port = get_app_port( cpe: CPE ) ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "2.8.0", test_version2: "2.8.51" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.8.52", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.4.0", test_version2: "3.4.34" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.4.35", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "4.2.0", test_version2: "4.2.11" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.2.12", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "4.3.0", test_version2: "4.3.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.3.8", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

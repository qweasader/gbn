# Copyright (C) 2021 Greenbone Networks GmbH
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

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118255");
  script_version("2022-06-29T10:11:11+0000");
  script_tag(name:"last_modification", value:"2022-06-29 10:11:11 +0000 (Wed, 29 Jun 2022)");
  script_tag(name:"creation_date", value:"2021-11-01 11:45:13 +0100 (Mon, 01 Nov 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-27 17:05:00 +0000 (Mon, 27 Jun 2022)");

  script_cve_id("CVE-2016-0718", "CVE-2016-4472");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python < 2.7.14, 3.3.x < 3.3.7, 3.4.x < 3.4.7, 3.5.x < 3.5.4, 3.6.x < 3.6.2 Expat 2.2 (bpo-29591) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Python is prone to various security vulnerabilities in bundled
  expat.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2016-0718: Expat allows context-dependent attackers to cause a denial of service (crash) or
  possibly execute arbitrary code via a malformed input document, which triggers a buffer overflow.

  - CVE-2016-4472: The overflow protection in Expat is removed by compilers with certain optimization
  settings, which allows remote attackers to cause a denial of service (crash) or possibly execute
  arbitrary code via crafted XML data.

  NOTE: this vulnerability exists because of an incomplete fix for CVE-2015-1283 and CVE-2015-2716.");

  script_tag(name:"affected", value:"Python prior to version 2.7.14, versions 3.3.x prior to 3.3.7,
  3.4.x prior to 3.4.7, 3.5.x prior to 3.5.3 and 3.6.x prior to 3.6.2.");

  script_tag(name:"solution", value:"Update to version 2.7.14, 3.3.7, 3.4.7, 3.5.4, 3.6.2 or later.");

  script_xref(name:"URL", value:"https://python-security.readthedocs.io/vuln/expat-2.2.html");
  script_xref(name:"Advisory-ID", value:"bpo-29591");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"2.7.14" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"2.7.14", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.3.0", test_version2:"3.3.6" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.3.7", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.4.0", test_version2:"3.4.6" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.4.7", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.5.0", test_version2:"3.5.3" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.5.4", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.6.0", test_version2:"3.6.1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.6.2", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

# Copyright (C) 2022 Greenbone Networks GmbH
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

CPE = "cpe:/a:gitlab:gitlab";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170052");
  script_version("2022-04-04T03:03:57+0000");
  script_tag(name:"last_modification", value:"2022-04-04 03:03:57 +0000 (Mon, 04 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-03-23 20:50:27 +0000 (Wed, 23 Mar 2022)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-17 15:17:00 +0000 (Wed, 17 Jun 2020)");

  script_cve_id("CVE-2020-13270");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("GitLab 11.3.x - 12.9.7, 12.10.x - 12.10.6, 13.0.0 Incorrect Permissions Check Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_gitlab_consolidation.nasl");
  script_mandatory_keys("gitlab/detected");

  script_tag(name:"summary", value:"GitLab is prone to an incorrect permissions check
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Missing permission check on fork relation creation in GitLab
  allows guest users to create a fork relation on restricted public projects via API.");

  script_tag(name:"affected", value:"GitLab version 11.3.x through 12.9.7, 12.10.x through 12.10.6 and
  13.0.0.");

  script_tag(name:"solution", value:"Update to version 12.9.8, 12.10.7, 13.0.1 or later.");

  script_xref(name:"URL", value:"https://gitlab.com/gitlab-org/cves/-/blob/master/2020/CVE-2020-13270.json");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if ( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if ( version_in_range( version:version, test_version:"11.3.0", test_version2:"12.9.7" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"12.9.8", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}


if ( version_in_range( version:version, test_version:"12.10.0", test_version2:"12.10.6" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"12.10.7", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if ( version_is_equal( version:version, test_version:"13.0.0" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"13.0.1", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

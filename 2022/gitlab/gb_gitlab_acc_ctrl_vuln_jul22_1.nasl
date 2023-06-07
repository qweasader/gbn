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
  script_oid("1.3.6.1.4.1.25623.1.0.170155");
  script_version("2022-08-11T10:10:35+0000");
  script_tag(name:"last_modification", value:"2022-08-11 10:10:35 +0000 (Thu, 11 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-08-08 19:18:44 +0000 (Mon, 08 Aug 2022)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_cve_id("CVE-2022-2095");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("GitLab 13.7.x - 15.0.4, 15.1.x - 15.1.3, 15.2 Improper Access Control Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_gitlab_consolidation.nasl");
  script_mandatory_keys("gitlab/detected");

  script_tag(name:"summary", value:"GitLab is prone to an improper access control vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An improper access control check in GitLab CE/EE  allows a
  malicious authenticated user to view a public project's Deploy Key's public fingerprint and name
  when that key has write permission.");

  script_tag(name:"affected", value:"GitLab version 13.7.x through 15.0.4, 15.1.x through 15.1.3
  and 15.2.");

  script_tag(name:"solution", value:"Update to version 15.0.5, 15.1.4, 15.2.1 or later.");

  script_xref(name:"URL", value:"https://about.gitlab.com/releases/2022/07/28/security-release-gitlab-15-2-1-released/");
  script_xref(name:"URL", value:"https://gitlab.com/gitlab-org/cves/-/blob/master/2022/CVE-2022-2095.json");

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

if ( version_in_range( version:version, test_version:"13.7.0", test_version2:"15.0.4" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"15.0.5", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}


if ( version_in_range( version:version, test_version:"15.1.0", test_version2:"15.1.3" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"15.1.4", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if ( version_is_equal( version:version, test_version:"15.2.0" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"15.2.1", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

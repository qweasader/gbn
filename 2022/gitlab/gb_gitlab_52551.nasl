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
  script_oid("1.3.6.1.4.1.25623.1.0.170058");
  script_version("2022-04-04T03:03:57+0000");
  script_tag(name:"last_modification", value:"2022-04-04 03:03:57 +0000 (Mon, 04 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-03-25 19:01:02 +0000 (Fri, 25 Mar 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-21 17:57:00 +0000 (Fri, 21 Dec 2018)");

  script_cve_id("CVE-2018-18642");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("GitLab 10.4.x - 11.2.6, 11.3.x - 11.3.7, 11.4.x - 11.4.2 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_gitlab_consolidation.nasl");
  script_mandatory_keys("gitlab/detected");

  script_tag(name:"summary", value:"GitLab is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Links in Security Reports & License Management are vulnerable to
  XSS attacks.");

  script_tag(name:"affected", value:"GitLab version 10.4.x through 11.2.6, 11.3.x through 11.3.7 and
  11.4.x through 11.4.2.");

  script_tag(name:"solution", value:"Update to version 11.2.7, 11.3.8, 11.4.3 or later.");

  script_xref(name:"URL", value:"https://gitlab.com/gitlab-org/gitlab-foss/-/issues/52551");

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

if ( version_in_range( version:version, test_version:"10.4.0", test_version2:"11.2.6" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"11.2.7", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if ( version_in_range( version:version, test_version:"11.3.0", test_version2:"11.3.7" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"11.3.8", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if ( version_in_range( version:version, test_version:"11.4.0", test_version2:"11.4.2" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"11.4.3", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

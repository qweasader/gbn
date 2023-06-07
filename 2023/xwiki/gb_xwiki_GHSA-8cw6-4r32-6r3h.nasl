# Copyright (C) 2023 Greenbone Networks GmbH
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

CPE = "cpe:/a:xwiki:xwiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170345");
  script_version("2023-03-09T10:20:45+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:20:45 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-06 09:03:39 +0000 (Mon, 06 Mar 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2023-26055");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("XWiki 3.1-milestone-1 < 13.10.9, 14.x < 14.4.4, 14.5.x < 14.7-rc-1 Privilege Escalation Vulnerability (GHSA-8cw6-4r32-6r3h)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_xwiki_enterprise_detect.nasl");
  script_mandatory_keys("xwiki/detected");

  script_tag(name:"summary", value:"Xwiki is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Any user can edit his own profile and inject code which is going
  to be executed with programming right.");

  script_tag(name:"affected", value:"XWiki version 3.1-milestone-1 prior to 13.10.9, 14.x prior to
  14.4.4 and 14.5.x prior to 14.7-rc-1.");

  script_tag(name:"solution", value:"Update to version 13.10.9, 14.4.4, 14.7-rc-1 or later.");

  script_xref(name:"URL", value:"https://github.com/xwiki/xwiki-commons/security/advisories/GHSA-8cw6-4r32-6r3h");
  script_xref(name:"url", value:"https://jira.xwiki.org/browse/XWIKI-19793");
  script_xref(name:"url", value:"https://jira.xwiki.org/browse/XWIKI-19794");
  script_xref(name:"url", value:"https://jira.xwiki.org/browse/XCOMMONS-2498");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if ( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range_exclusive( version:version, test_version_lo:"3.1-milestone-1", test_version_up:"13.10.9" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"13.10.9", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"14.0", test_version_up:"14.4.4" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"14.4.4", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if ( version_in_range_exclusive( version:version, test_version_lo:"14.5", test_version_up:"14.7-rc-1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"14.7-rc-1", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

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

CPE = "cpe:/a:xwiki:xwiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170246");
  script_version("2022-11-28T10:12:42+0000");
  script_tag(name:"last_modification", value:"2022-11-28 10:12:42 +0000 (Mon, 28 Nov 2022)");
  script_tag(name:"creation_date", value:"2022-11-24 14:20:59 +0000 (Thu, 24 Nov 2022)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_cve_id("CVE-2022-41936");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("XWiki 8.1 < 13.10.8, 14.x < 14.4.3, 14.5.x < 14.6 Exposure of Private Information Vulnerability (GHSA-p88w-fhxw-xvcc)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_xwiki_enterprise_detect.nasl");
  script_mandatory_keys("xwiki/detected");

  script_tag(name:"summary", value:"Xwiki is prone to an exposure of private information
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The modifications rest endpoint does not filter out entries
  according to the user's rights. Therefore, information hidden from unauthorized users are exposed
   though the modifications rest endpoint (e.g., comments, page names etc.).");

  script_tag(name:"affected", value:"XWiki version 8.1 prior to 13.10.8, 14.x prior to 14.4.3
  and 14.5.x prior to 14.6.");

  script_tag(name:"solution", value:"Update to version 13.10.8, 14.4.3, 14.6 or later.");

  script_xref(name:"URL", value:"https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-p88w-fhxw-xvcc");

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

if( version_in_range_exclusive( version:version, test_version_lo:"8.1", test_version_up:"13.10.8" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"13.10.8", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"14.0", test_version_up:"14.4.3" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"14.4.3", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if ( version_in_range_exclusive( version:version, test_version_lo:"14.5", test_version_up:"14.6" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"14.6", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
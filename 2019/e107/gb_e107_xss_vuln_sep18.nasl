# Copyright (C) 2019 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.112233");
  script_version("2021-09-07T08:01:28+0000");
  script_tag(name:"last_modification", value:"2021-09-07 08:01:28 +0000 (Tue, 07 Sep 2021)");
  script_tag(name:"creation_date", value:"2019-06-20 13:11:00 +0200 (Thu, 20 Jun 2019)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-20 13:17:00 +0000 (Thu, 20 Jun 2019)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"Mitigation");

  script_cve_id("CVE-2018-17423");

  script_name("e107 <= 2.2.1 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("e107_detect.nasl");
  script_mandatory_keys("e107/installed");

  script_tag(name:"summary", value:"e107 is prone to a cross-site scripting (XSS) vulnerability via e107_admin/comment.php.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacker to inject
  malicious script content into the affected site.");

  script_tag(name:"affected", value:"e107 through version 2.1.9.");

  script_tag(name:"solution", value:"To mitigate this vulnerability the vendor recommends to disable the functionality
  under 'Preferences - Text rendering - Class' by setting the ability to post to 'No One (inactive)'. This will be the
  default setting in the upcoming 2.3.0 release.");

  script_xref(name:"URL", value:"https://github.com/Kiss-sh0t/e107_v2.1.9_XSS_poc");

  exit(0);
}

CPE = "cpe:/a:e107:e107";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
path = infos["location"];

if( version_is_less( version: version, test_version: "2.3.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "Disable the ability to post like described in the solution.", install_path: path );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

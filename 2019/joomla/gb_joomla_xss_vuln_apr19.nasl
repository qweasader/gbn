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
  script_oid("1.3.6.1.4.1.25623.1.0.112586");
  script_version("2021-09-02T13:01:30+0000");
  script_tag(name:"last_modification", value:"2021-09-02 13:01:30 +0000 (Thu, 02 Sep 2021)");
  script_tag(name:"creation_date", value:"2019-05-22 13:23:11 +0200 (Wed, 22 May 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-20 15:32:00 +0000 (Mon, 20 May 2019)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-11809");

  script_name("Joomla! 1.7.0 <= 3.9.5 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");

  script_tag(name:"summary", value:"Joomla! is prone to a cross-site scripting vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The debug views of com_users do not properly escape user supplied data,
  which leads to a potential XSS attack vector.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to inject
  malicious content into the affected site.");
  script_tag(name:"affected", value:"Joomla! versions 1.7.0 through 3.9.5.");
  script_tag(name:"solution", value:"Update to version 3.9.6 or later.");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/780-20190501-core-xss-in-com-users-acl-debug-view");

  exit(0);
}

CPE = "cpe:/a:joomla:joomla";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
path = infos["location"];

if( version_in_range( version: version, test_version: "1.7.0", test_version2: "3.9.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.9.6", install_path: path );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

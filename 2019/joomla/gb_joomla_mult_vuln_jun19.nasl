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
  script_oid("1.3.6.1.4.1.25623.1.0.113390");
  script_version("2023-01-31T10:08:41+0000");
  script_tag(name:"last_modification", value:"2023-01-31 10:08:41 +0000 (Tue, 31 Jan 2023)");
  script_tag(name:"creation_date", value:"2019-06-13 11:57:50 +0000 (Thu, 13 Jun 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-30 16:03:00 +0000 (Mon, 30 Jan 2023)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-12764", "CVE-2019-12765", "CVE-2019-12766");

  script_name("Joomla! < 3.9.7 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");

  script_tag(name:"summary", value:"Joomla! is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - The update server URL of com_joomlaupdate can be manipulated by non Super-Admin users.

  - The subform fieldtype does not sufficiently filter or validate input of subfields.
    This leads to XSS attack vectors.

  - The CSV export of com_actionslogs is vulnerable to CSV injection.");
  script_tag(name:"impact", value:"Successful exploitation can have effects ranging from disclosure of sensitive information
  to executing arbitrary code on the target machine.");
  script_tag(name:"affected", value:"Joomla! through version 3.9.6.");
  script_tag(name:"solution", value:"Update to version 3.9.7.");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/785-20190603-core-acl-hardening-of-com-joomlaupdate");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/108729");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/108735");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/108736");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/783-20190601-core-csv-injection-in-com-actionlogs");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/784-20190602-core-xss-in-subform-field");

  exit(0);
}

CPE = "cpe:/a:joomla:joomla";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "3.9.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.9.7", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

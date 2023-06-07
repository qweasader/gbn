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

CPE = "cpe:/a:snapcreek:duplicator";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124143");
  script_version("2022-08-25T10:12:37+0000");
  script_tag(name:"last_modification", value:"2022-08-25 10:12:37 +0000 (Thu, 25 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-08-23 10:05:00 +0100 (Tue, 23 Aug 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_cve_id("CVE-2022-2551");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Duplicator Plugin < 1.4.7 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/duplicator/detected");

  script_tag(name:"summary", value:"The WordPress plugin Duplicator is prone to an information
  disclosure vulnerability.");

  script_tag(name:"insight", value:"The Duplicator WordPress plugin discloses the url of the a
  backup to unauthenticated visitors accessing the main installer endpoint of the plugin, if the
  installer script has been run once by an administrator, allowing download of the full site
  backup without authenticating.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"WordPress Duplicator plugin version prior to 1.4.7.");

  script_tag(name:"solution", value:"Update to version 1.4.7 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/f27d753e-861a-4d8d-9b9a-6c99a8a7ebe0");
  script_xref(name:"URL", value:"https://github.com/SecuriTrust/CVEsLab/tree/main/CVE-2022-2551");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if ( version_is_less( version: version, test_version: "1.4.7" )) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.4.7", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );

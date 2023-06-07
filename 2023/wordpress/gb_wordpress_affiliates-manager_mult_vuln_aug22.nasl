# Copyright (C) 2023 Greenbone Networks GmbH
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

CPE = "cpe:/a:wpaffiliatemanager:affiliates_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170312");
  script_version("2023-02-21T10:19:50+0000");
  script_tag(name:"last_modification", value:"2023-02-21 10:19:50 +0000 (Tue, 21 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-17 19:58:20 +0000 (Fri, 17 Feb 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2022-2798", "CVE-2022-2799");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Affiliates Manager Plugin < 2.9.14 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/affiliates-manager/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Affiliates Manager' is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-2798: Affiliate CSV injection

  - CVE-2022-2799: Stored XSS

  - Arbitrary affiliates & creatives deletion via CSRF

  - Reflected XSS");

  script_tag(name:"affected", value:"WordPress Affiliates Manager plugin prior to version 2.9.14.");

  script_tag(name:"solution", value:"Update to version 2.9.14.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/f169567d-c682-4abe-94df-a9d00be90edd");
  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/4385370e-cf99-4249-b2c1-90cbfa8378a4");
  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/e4328bb5-cf74-496f-a66d-5b3f83a9ef51");
  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/2e2faa0d-a751-404a-ae15-e0fafc824bc0");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"2.9.14" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"2.9.14", install_path:location );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );

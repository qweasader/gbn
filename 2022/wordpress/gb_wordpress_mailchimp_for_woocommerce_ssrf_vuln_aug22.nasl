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

CPE = "cpe:/a:mailchimp:mailchimp_for_woocommerce";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170183");
  script_version("2023-10-19T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-10-19 05:05:21 +0000 (Thu, 19 Oct 2023)");
  script_tag(name:"creation_date", value:"2022-10-04 14:04:48 +0000 (Tue, 04 Oct 2022)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-01 06:46:00 +0000 (Thu, 01 Sep 2022)");

  script_cve_id("CVE-2022-2556");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Mailchimp for WooCommerce Plugin < 2.7.2 SSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/mailchimp-for-woocommerce/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Mailchimp for WooCommerce' is prone to a
  server-side request forgery (SSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin has an AJAX action that allows high privilege users to
  perform a POST request on behalf of the server to the internal network/LAN, the body of the request
  is also appended to the response so it can be used to scan private network for example");

  script_tag(name:"affected", value:"WordPress Mailchimp for WooCommerce plugin prior to version
  2.7.2.");

  script_tag(name:"solution", value:"Update to version 2.7.2 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/f2a59eaa-6b44-4098-912f-823289cf33b0");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if ( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if ( version_is_less( version:version, test_version:"2.7.2" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"2.7.2", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

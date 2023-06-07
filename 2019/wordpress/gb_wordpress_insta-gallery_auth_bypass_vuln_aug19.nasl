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
  script_oid("1.3.6.1.4.1.25623.1.0.113508");
  script_version("2022-12-05T10:11:03+0000");
  script_tag(name:"last_modification", value:"2022-12-05 10:11:03 +0000 (Mon, 05 Dec 2022)");
  script_tag(name:"creation_date", value:"2019-09-11 12:24:05 +0000 (Wed, 11 Sep 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-03 21:10:00 +0000 (Tue, 03 Sep 2019)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-15779");

  script_name("WordPress WP Social Feed Gallery Plugin < 2.4.8 Authentication Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/insta-gallery/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'WP Social Feed Gallery' is prone to
  an authentication bypass vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"There is no nonce validation for
  qligg_dismiss_notice or qligg_form_item_delete.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to
  perform actions without the need of authentication.");
  script_tag(name:"affected", value:"WordPress WP Social Feed Gallery plugin through version 2.4.7.");
  script_tag(name:"solution", value:"Update to version 2.4.8 or later.");

  script_xref(name:"URL", value:"https://wpvulndb.com/vulnerabilities/9853");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/insta-gallery/#developers");

  exit(0);
}

CPE = "cpe:/a:quadlayers:wp_social_feed_gallery";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "2.4.8" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.4.8", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

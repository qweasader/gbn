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
  script_oid("1.3.6.1.4.1.25623.1.0.113485");
  script_version("2022-11-14T10:12:51+0000");
  script_tag(name:"last_modification", value:"2022-11-14 10:12:51 +0000 (Mon, 14 Nov 2022)");
  script_tag(name:"creation_date", value:"2019-08-29 13:08:29 +0000 (Thu, 29 Aug 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-21 13:39:00 +0000 (Wed, 21 Aug 2019)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-14800");

  script_name("WordPress FV Flowplayer Video Player Plugin < 7.3.15.727 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/fv-wordpress-flowplayer/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'FV Flowplayer Video Player' is prone to an information disclosure vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Guests can obtain the email subscription list in CSV format
  via the wp-admin/admin-post.php?page=fvplayer&gv-email-export=1 URI.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to access sensitive information.");
  script_tag(name:"affected", value:"WordPress FV Flowplayer Video Player plugin through version 7.3.14.727.");
  script_tag(name:"solution", value:"Update to version 7.3.15.727 or later.");

  script_xref(name:"URL", value:"https://www.pluginvulnerabilities.com/2019/05/15/information-disclosure-vulnerability-in-fv-player-fv-flowplayer-video-player/");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/fv-wordpress-flowplayer/#developers");

  exit(0);
}

CPE = "cpe:/a:foliovision:fv_flowplayer_video_player";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "7.3.15.727" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.3.15.727", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

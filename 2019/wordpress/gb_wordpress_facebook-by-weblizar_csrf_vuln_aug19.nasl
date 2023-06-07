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
  script_oid("1.3.6.1.4.1.25623.1.0.113510");
  script_version("2022-11-14T10:12:51+0000");
  script_tag(name:"last_modification", value:"2022-11-14 10:12:51 +0000 (Mon, 14 Nov 2022)");
  script_tag(name:"creation_date", value:"2019-09-11 12:55:32 +0000 (Wed, 11 Sep 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-30 19:35:00 +0000 (Fri, 30 Aug 2019)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-15781");

  script_name("WordPress Social LikeBox & Feed Plugin < 2.8.5 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/facebook-by-weblizar/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Social LikeBox & Feed' is prone to
  a cross-site request forgery (CSRF) vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to
  perform actions in the context of another user.");
  script_tag(name:"affected", value:"WordPress Social LikeBox & Feed plugin through version 2.8.4.");
  script_tag(name:"solution", value:"Update to version 2.8.5 or later.");

  script_xref(name:"URL", value:"https://wpvulndb.com/vulnerabilities/9851");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/facebook-by-weblizar/#developers");

  exit(0);
}

CPE = "cpe:/a:weblizar:social_likebox_%26_feed";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "2.8.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.8.5", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

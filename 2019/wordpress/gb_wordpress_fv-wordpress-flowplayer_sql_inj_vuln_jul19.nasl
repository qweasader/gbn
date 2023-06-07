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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112608");
  script_version("2023-03-02T10:19:53+0000");
  script_tag(name:"last_modification", value:"2023-03-02 10:19:53 +0000 (Thu, 02 Mar 2023)");
  script_tag(name:"creation_date", value:"2019-07-18 10:43:00 +0000 (Thu, 18 Jul 2019)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-01 16:22:00 +0000 (Wed, 01 Mar 2023)");

  script_cve_id("CVE-2019-13573");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress FV Flowplayer Video Player Plugin < 7.3.19.727 SQL Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/fv-wordpress-flowplayer/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'FV Flowplayer' is prone to an SQL injection vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability would allow a remote attacker
  to execute arbitrary SQL commands on the affected system.");

  script_tag(name:"affected", value:"WordPress FV Flowplayer plugin before version 7.3.19.727.");

  script_tag(name:"solution", value:"Update to version 7.3.19.727 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/fv-wordpress-flowplayer/#developers");
  script_xref(name:"URL", value:"https://fortiguard.com/zeroday/FG-VD-19-097");
  script_xref(name:"URL", value:"https://plugins.trac.wordpress.org/changeset/2121566/fv-wordpress-flowplayer/trunk/models/db.php");

  exit(0);
}

CPE = "cpe:/a:foliovision:fv_flowplayer_video_player";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "7.3.19.727" )) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.3.19.727", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );

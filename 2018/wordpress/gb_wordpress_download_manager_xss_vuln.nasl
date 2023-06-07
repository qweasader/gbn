###############################################################################
# OpenVAS Vulnerability Test
#
# WordPress Download Manager Plugin XSS Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
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
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140719");
  script_version("2022-07-20T10:33:02+0000");
  script_tag(name:"last_modification", value:"2022-07-20 10:33:02 +0000 (Wed, 20 Jul 2022)");
  script_tag(name:"creation_date", value:"2018-01-23 10:22:04 +0700 (Tue, 23 Jan 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-05 12:21:00 +0000 (Tue, 05 May 2020)");

  script_cve_id("CVE-2017-18032");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Download Manager Plugin < 2.9.51 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/download-manager/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Download Manager' is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"insight", value:"The XSS flaw exists via the id parameter in a
  wpdm_generate_password action to wp-admin/admin-ajax.php.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"WordPress Download Manager plugin 2.9.51 and prior.");

  script_tag(name:"solution", value:"Update to version 2.9.52 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/download-manager/#developers");
  script_xref(name:"URL", value:"https://security.dxw.com/advisories/xss-download-manager/");

  exit(0);
}

CPE = "cpe:/a:wpdownloadmanager:wordpress_download_manager";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if ( version_is_less( version: version, test_version: "2.9.52" )) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.9.52", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );

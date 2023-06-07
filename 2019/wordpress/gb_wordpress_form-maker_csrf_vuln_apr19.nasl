# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.112573");
  script_version("2022-11-14T10:12:51+0000");
  script_tag(name:"last_modification", value:"2022-11-14 10:12:51 +0000 (Mon, 14 Nov 2022)");
  script_tag(name:"creation_date", value:"2019-05-08 14:00:00 +0200 (Wed, 08 May 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_cve_id("CVE-2019-11590");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Form Maker Plugin < 1.13.5 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/form-maker/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Form Maker' is prone to a CSRF vulnerability.");
  script_tag(name:"insight", value:"The 10Web Form Maker plugin allows CSRF via the wp-admin/admin-ajax.php action parameter,
  resulting in a local file inclusion via directory traversal, because there can be a discrepancy between the $_POST['action']
  value and the $_GET['action'] value, with the latter being unsanitized.");
  script_tag(name:"affected", value:"WordPress Form Maker plugin before version 1.13.5.");
  script_tag(name:"solution", value:"Update to version 1.13.5 or later.");

  script_xref(name:"URL", value:"https://lists.openwall.net/full-disclosure/2019/04/05/11");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/form-maker/#developers");

  exit(0);
}

CPE = "cpe:/a:10web:form_maker";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "1.13.5" )) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.13.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );

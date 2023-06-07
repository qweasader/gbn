# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.112763");
  script_version("2023-01-18T10:11:02+0000");
  script_tag(name:"last_modification", value:"2023-01-18 10:11:02 +0000 (Wed, 18 Jan 2023)");
  script_tag(name:"creation_date", value:"2020-06-02 10:23:00 +0000 (Tue, 02 Jun 2020)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-28 19:42:00 +0000 (Thu, 28 May 2020)");

  script_cve_id("CVE-2020-13642", "CVE-2020-13643");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Page Builder by SiteOrigin Plugin < 2.10.16 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/siteorigin-panels/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Page Builder by SiteOrigin' is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The action_builder_content function and live editor feature did
  not do any nonce verification, allowing for requests to be forged on behalf of an administrator.
  The panels_data $_POST variable allows for malicious JavaScript to be executed in the victim's
  browser.");

  script_tag(name:"impact", value:"Successful exploitation of this issue may allow an attacker to
  execute malicious JavaScript in the victim's browser.");

  script_tag(name:"affected", value:"WordPress Page Builder by SiteOrigin plugin prior to
  version 2.10.16.");

  script_tag(name:"solution", value:"Update the plugin to version 2.10.16 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2020/05/vulnerabilities-patched-in-page-builder-by-siteorigin-affects-over-1-million-sites/");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/siteorigin-panels/#developers");

  exit(0);
}

CPE = "cpe:/a:siteorigin:page_builder";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "2.10.16" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.10.16", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );

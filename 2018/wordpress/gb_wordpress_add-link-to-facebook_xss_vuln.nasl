###############################################################################
# OpenVAS Vulnerability Test
#
# WordPress Add Link to Facebook Plugin Stored XSS Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.112178");
  script_version("2022-11-07T10:13:06+0000");
  script_tag(name:"last_modification", value:"2022-11-07 10:13:06 +0000 (Mon, 07 Nov 2022)");
  script_tag(name:"creation_date", value:"2018-01-05 14:16:51 +0100 (Fri, 05 Jan 2018)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-18 15:32:00 +0000 (Thu, 18 Jan 2018)");

  script_cve_id("CVE-2018-5214");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("WordPress Add Link to Facebook Plugin <= 2.3 Stored XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/add-link-to-facebook/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Download Manager' is prone to a stored
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"insight", value:"The stored XSS flaw exists in the al2fb_facebook_id parameter of
  wp-admin/profile.php.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"WordPress Add Link to Facebook plugin up to and including version 2.3.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_xref(name:"URL", value:"https://github.com/d4wner/Vulnerabilities-Report/blob/master/Add-Link-to-Facebook.md");
  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/5436d4f3-4f7e-41de-a628-49ebd3db7a81");

  exit(0);
}

CPE = "cpe:/a:add_link_to_facebook_project:add_link_to_facebook";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if ( version_is_less_equal( version: version, test_version: "2.3" )) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );

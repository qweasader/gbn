# Copyright (C) 2020 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113737");
  script_version("2021-07-05T11:01:33+0000");
  script_tag(name:"last_modification", value:"2021-07-05 11:01:33 +0000 (Mon, 05 Jul 2021)");
  script_tag(name:"creation_date", value:"2020-08-05 09:32:19 +0000 (Wed, 05 Aug 2020)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-04 18:16:00 +0000 (Tue, 04 Aug 2020)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-16131");

  script_name("Tiki Wiki < 21.2 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_tikiwiki_detect.nasl");
  script_mandatory_keys("TikiWiki/installed");

  script_tag(name:"summary", value:"Tiki Wiki is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability exists because some patterns
  are not properly considered in lib/core/TikiFilter/PreventXss.php.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker
  to inject arbitrary HTML and JavaScript into the site.");

  script_tag(name:"affected", value:"Tiki Wiki through version 21.1.");

  script_tag(name:"solution", value:"Update to version 21.2.");

  script_xref(name:"URL", value:"https://gitlab.com/tikiwiki/tiki/-/commit/d12d6ea7b025d3b3f81c8a71063fe9f89e0c4bf1");

  exit(0);
}

CPE = "cpe:/a:tiki:tikiwiki_cms/groupware";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "21.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "21.2", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

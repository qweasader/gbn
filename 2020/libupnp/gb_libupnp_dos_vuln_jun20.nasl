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
  script_oid("1.3.6.1.4.1.25623.1.0.113699");
  script_version("2021-07-07T02:00:46+0000");
  script_tag(name:"last_modification", value:"2021-07-07 02:00:46 +0000 (Wed, 07 Jul 2021)");
  script_tag(name:"creation_date", value:"2020-06-08 11:39:44 +0000 (Mon, 08 Jun 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-08 01:15:00 +0000 (Mon, 08 Mar 2021)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-13848");

  script_name("lipupnp <= 1.12.1 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_libupnp_consolidation.nasl");
  script_mandatory_keys("libupnp/detected");

  script_tag(name:"summary", value:"libupnp is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability can be exploited via
  a crafted SSDP message due to a NULL pointer dereference in the functions
  FindServiceControlURLPath and FindServiceEventURLPath in genlib/service_table/service_table.c.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to crash the service.");

  script_tag(name:"affected", value:"libupnp through version 1.12.1.");

  script_tag(name:"solution", value:"Update to version 1.12.2 or later.");

  script_xref(name:"URL", value:"https://github.com/pupnp/pupnp/issues/177");
  script_xref(name:"URL", value:"https://github.com/pupnp/pupnp/commit/c805c1de1141cb22f74c0d94dd5664bda37398e0");

  exit(0);
}

CPE = "cpe:/a:libupnp_project:libupnp";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less_equal( version: vers, test_version: "1.12.1" ) ) {
  report = report_fixed_ver( installed_version: vers, fixed_version: "1.12.2", install_path: path );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

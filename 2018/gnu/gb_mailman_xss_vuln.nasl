# Copyright (C) 2018 Greenbone Networks GmbH
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

CPE = "cpe:/a:gnu:mailman";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113097");
  script_version("2022-07-20T10:33:02+0000");
  script_tag(name:"last_modification", value:"2022-07-20 10:33:02 +0000 (Wed, 20 Jul 2022)");
  script_tag(name:"creation_date", value:"2018-01-31 13:35:40 +0100 (Wed, 31 Jan 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-10 19:39:00 +0000 (Tue, 10 Nov 2020)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-5950");

  script_name("Mailman < 2.1.26 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("mailman_detect.nasl");
  script_mandatory_keys("gnu_mailman/detected");

  script_tag(name:"summary", value:"Mailman is prone to a cross-site scripting (XSS) vulnerability
  in the web UI.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to inject
  arbitrary web script or HTML.");

  script_tag(name:"affected", value:"GNU Mailman before version 2.1.26.");

  script_tag(name:"solution", value:"Update to version 2.1.26 or later.");

  script_xref(name:"URL", value:"https://www.mail-archive.com/mailman-users@python.org/msg70375.html");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! info = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

vers = info["version"];
path = info["location"];

if( version_is_less( version: vers, test_version: "2.1.26" ) ) {
  report = report_fixed_ver( installed_version: vers, fixed_version: "2.1.26", install_path: path );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

# Copyright (C) 2023 Greenbone Networks GmbH
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

CPE = "cpe:/a:memcached:memcached";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127322");
  script_version("2023-02-07T12:10:58+0000");
  script_tag(name:"last_modification", value:"2023-02-07 12:10:58 +0000 (Tue, 07 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-06 05:30:42 +0000 (Mon, 06 Feb 2023)");
  script_tag(name:"cvss_base", value:"2.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:N/I:N/A:P");

  script_cve_id("CVE-2021-37519");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Memcached 1.5.15 < 1.6.10 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_memcached_detect.nasl", "gb_memcached_detect_udp.nasl");
  script_mandatory_keys("memcached/detected");

  script_tag(name:"summary", value:"Memcached is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker is able to cause a denial of service via crafted
  authenticattion file due to a buffer overflow in authfile.c.");

  script_tag(name:"affected", value:"Memcached version 1.5.15 prior to 1.6.10.");

  script_tag(name:"solution", value:"Update to version 1.6.10 or later.");

  script_xref(name:"URL", value:"https://github.com/memcached/memcached/issues/805");
  script_xref(name:"URL", value:"https://github.com/memcached/memcached/pull/806");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_proto( cpe: CPE, port: port ) )
  exit( 0 );

version = infos["version"];
proto = infos["proto"];

if( version_in_range_exclusive( version: version, test_version_lo: "1.5.15", test_version_up: "1.6.10" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.6.10" );
  security_message( port: port, proto: proto, data: report );
  exit( 0 );
}

exit( 99 );

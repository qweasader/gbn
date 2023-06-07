# Copyright (C) 2009 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900914");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-08-20 09:27:17 +0200 (Thu, 20 Aug 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2415");
  script_name("Memcached 'CVE-2009-2415' Multiple Buffer Overflow Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_memcached_detect.nasl", "gb_memcached_detect_udp.nasl");
  script_mandatory_keys("memcached/detected");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2009/Aug/0055.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35989");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary
  code on the affected system via readily available network utilities.");

  script_tag(name:"affected", value:"Memcached version 1.1.12 and 1.2.2.");

  script_tag(name:"insight", value:"Heap overflow errors occur due to integer conversions when
  parsing certain length attributes.");

  script_tag(name:"summary", value:"Memcached is prone to multiple buffer overflow
  vulnerabilities.");

  script_tag(name:"solution", value:"Update to a later version.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_proto( cpe:CPE, port:port ) )
  exit( 0 );

vers = infos["version"];
proto = infos["proto"];

if( version_is_equal( version:vers, test_version:"1.1.12" ) ||
    version_is_equal( version:vers, test_version:"1.2.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references" );
  security_message( port:port, proto:proto, data:report );
  exit( 0 );
}

exit( 99 );
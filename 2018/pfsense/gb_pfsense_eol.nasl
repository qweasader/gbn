###############################################################################
# OpenVAS Vulnerability Test
#
# pfSense End of Life (EOL) Detection
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:pfsense:pfsense";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108435");
  script_version("2020-12-09T13:05:49+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-12-09 13:05:49 +0000 (Wed, 09 Dec 2020)");
  script_tag(name:"creation_date", value:"2018-04-07 12:17:00 +0200 (Sat, 07 Apr 2018)");
  script_name("pfSense End of Life (EOL) Detection");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_pfsense_detect.nasl");
  script_mandatory_keys("pfsense/installed");

  script_xref(name:"URL", value:"https://lists.pfsense.org/pipermail/list/2012-April/002017.html");
  script_xref(name:"URL", value:"https://doc.pfsense.org/index.php/Versions_of_pfSense_and_FreeBSD");

  script_tag(name:"summary", value:"The pfSense version on the remote host has reached the End of Life (EOL) and should
  not be used anymore.");

  script_tag(name:"impact", value:"An EOL version of pfSense is not receiving any security updates from the vendor. Unfixed security vulnerabilities
  might be leveraged by an attacker to compromise the security of this host.");

  script_tag(name:"solution", value:"Update the pfSense version on the remote host to a still supported version.");

  script_tag(name:"vuldetect", value:"Checks if an EOL version is present on the target host.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("products_eol.inc");
include("list_array_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( ret = product_reached_eol( cpe:CPE, version:vers ) ) {
  report = build_eol_message( name:"pfSense",
                              cpe:CPE,
                              version:vers,
                              eol_version:ret["eol_version"],
                              eol_date:ret["eol_date"],
                              eol_type:"prod" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

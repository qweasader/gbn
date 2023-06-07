###############################################################################
# OpenVAS Vulnerability Test
#
# JBoss Operations Network End of Life (EOL) Detection (Windows)
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, https://www.greenbone.net
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113029");
  script_version("2020-12-09T13:05:49+0000");
  script_tag(name:"last_modification", value:"2020-12-09 13:05:49 +0000 (Wed, 09 Dec 2020)");
  script_tag(name:"creation_date", value:"2017-10-16 14:09:10 +0200 (Mon, 16 Oct 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("JBoss Operations Network End of Life (EOL) Detection (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_jboss_on_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("jboss_on/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"The JBoss Operations Network version on the remote
  host has reached the End of Life (EOL) and should not be used anymore.");

  script_tag(name:"impact", value:"An EOL version of JBoss Operations Network is
  not receiving any security updates from the vendor. Unfixed security vulnerabilities
  might be leveraged by an attacker to compromise the security of this host.");

  script_tag(name:"solution", value:"Update the JBoss Operations Network version on the
  remote host to a still supported version.");

  script_tag(name:"vuldetect", value:"Checks if an EOL version is present on the target host.");

  script_xref(name:"URL", value:"https://access.redhat.com/support/policy/updates/jboss_notes/#Life_cycle_dates");

  exit(0);
}

CPE = "cpe:/a:redhat:jboss_operations_network";

include("misc_func.inc");
include("products_eol.inc");
include("list_array_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( ret = product_reached_eol( cpe: CPE, version: version ) ) {
  report = build_eol_message( name: "JBoss Operations Network",
                              cpe: CPE,
                              version: version,
                              eol_version: ret["eol_version"],
                              eol_date: ret["eol_date"],
                              eol_type: "prod" );

  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );

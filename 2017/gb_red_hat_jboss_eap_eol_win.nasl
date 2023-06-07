# Copyright (C) 2017 Greenbone Networks GmbH
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113028");
  script_version("2022-03-28T13:20:55+0000");
  script_tag(name:"last_modification", value:"2022-03-28 13:20:55 +0000 (Mon, 28 Mar 2022)");
  script_tag(name:"creation_date", value:"2017-10-16 13:54:55 +0200 (Mon, 16 Oct 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Red Hat JBoss Enterprise Application Platform (EAP) End of Life (EOL) Detection - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_red_hat_jboss_eap_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("redhat/jboss/eap/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"The Red Hat JBoss Enterprise Application Platform (EAP) version
  on the remote host has reached the End of Life (EOL) and should not be used anymore.");

  script_tag(name:"impact", value:"An EOL version of Red Hat JBoss EAP is not receiving any security
  updates from the vendor. Unfixed security vulnerabilities might be leveraged by an attacker to
  compromise the security of this host.");

  script_tag(name:"solution", value:"Update the Red Hat JBoss EAP version on the remote host to a
  still supported version.");

  script_tag(name:"vuldetect", value:"Checks if an EOL version is present on the target host.");

  script_xref(name:"URL", value:"https://access.redhat.com/support/policy/updates/jboss_notes/#Life_cycle_dates");

  exit(0);
}

CPE = "cpe:/a:redhat:jboss_enterprise_application_platform";

include("misc_func.inc");
include("products_eol.inc");
include("list_array_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! version = get_app_version( cpe: CPE, port: port ) )
  exit( 0 );

if( ret = product_reached_eol( cpe: CPE, version: version ) ) {
  report = build_eol_message( name: "Red Hat JBoss Enterprise Application Platform (EAP)",
                              cpe: CPE,
                              version: version,
                              eol_version: ret["eol_version"],
                              eol_date: ret["eol_date"],
                              eol_type: "prod" );

  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );

# Copyright (C) 2015 Greenbone Networks GmbH
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

CPE = "cpe:/o:cisco:wireless_lan_controller_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105401");
  script_cve_id("CVE-2015-6311");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_version("2021-06-02T09:00:58+0000");
  script_tag(name:"last_modification", value:"2021-06-02 09:00:58 +0000 (Wed, 02 Jun 2021)");
  script_tag(name:"creation_date", value:"2015-10-14 14:24:59 +0200 (Wed, 14 Oct 2015)");

  script_name("Cisco Wireless LAN Controller 802.11i Management Frame DoS");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=41249");

  script_tag(name:"summary", value:"Cisco Wireless LAN Controller contains a vulnerability that could allow
  an unauthenticated, adjacent attacker to cause a denial of service condition.");

  script_tag(name:"impact", value:"An unauthenticated, adjacent attacker could exploit this vulnerability to
  cause a DoS condition on a targeted device.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to a failure to properly discard certain malformed
  values in an 802.11i management frame received from a wireless client. An attacker could trigger the vulnerability
  by submitting a crafted frame to an access point managed by the affected Cisco WLC.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"affected", value:"Cisco WLC Software releases 7.4(1.19), 7.3(101.0), and 7.0(240.0) are vulnerable.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_wlc_consolidation.nasl");
  script_mandatory_keys("cisco/wlc/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! vers = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( vers == "7.0.240.0" || vers == "7.3.101.0" || vers == "7.4.1.19" ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See advisory" );
  security_message( port:0, data:report );
  exit( 0 );
 }

exit( 99 );

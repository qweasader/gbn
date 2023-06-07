# Copyright (C) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/o:cisco:nx-os";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105713");
  script_version("2022-12-26T10:12:01+0000");
  script_tag(name:"last_modification", value:"2022-12-26 10:12:01 +0000 (Mon, 26 Dec 2022)");
  script_tag(name:"creation_date", value:"2016-05-12 16:37:11 +0200 (Thu, 12 May 2016)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2014-2200", "CVE-2014-3261", "CVE-2013-1191", "CVE-2014-2201");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Multiple Vulnerabilities in Cisco NX-OS-Based Products (cisco-sa-20140521-nxos)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_nx_os_consolidation.nasl");
  script_mandatory_keys("cisco/nx_os/detected", "cisco/nx_os/device", "cisco/nx_os/model");

  script_tag(name:"summary", value:"Cisco NX-OS-based products are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2014-2200: Virtual device context SSH privilege escalation

  - CVE-2014-3261: Smart call home buffer overflow

  - CVE-2013-1191: Virtual device context SSH key privilege escalation

  - CVE-2014-2201: Message transfer service denial of service");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140521-nxos");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=34245");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=34246");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=34248");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=34247");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! device = get_kb_item( "cisco/nx_os/device" ) )
  exit( 0 );

if( "Nexus" >!< device )
  exit( 0 );

if ( ! nx_model = get_kb_item( "cisco/nx_os/model" ) )
  exit( 0 );

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( nx_model =~ "^C?3[0-9]+" ) {
  affected = make_list(
    "5.0(3)U1(1)",
    "5.0(3)U1(1a)",
    "5.0(3)U1(1b)",
    "5.0(3)U1(1d)",
    "5.0(3)U1(2)",
    "5.0(3)U1(2a)"
  );
}

if( nx_model =~ "^C?4[0-9]+" ) {
  affected = make_list(
    "4.1(2)E1(1)",
    "4.1(2)E1(1b)",
    "4.1(2)E1(1d)",
    "4.1(2)E1(1e)",
    "4.1(2)E1(1f)",
    "4.1(2)E1(1g)",
    "4.1(2)E1(1h)",
    "4.1(2)E1(1i)",
    "4.1(2)E1(1j)"
  );
}

if( nx_model =~ "^C?5[0-9]+" ) {
  affected = make_list(
    "4.0(0)N1(1a)",
    "4.0(0)N1(2)",
    "4.0(0)N1(2a)",
    "4.0(1a)N1(1)",
    "4.0(1a)N1(1a)",
    "4.0(1a)N2(1)",
    "4.0(1a)N2(1a)",
    "4.1(3)N1(1)",
    "4.1(3)N1(1a)",
    "4.1(3)N2(1)",
    "4.1(3)N2(1a)",
    "4.2(1)N1(1)",
    "4.2(1)N2(1)",
    "4.2(1)N2(1a)",
    "5.0(2)N1(1)",
    "5.0(2)N2(1)",
    "5.0(2)N2(1a)",
    "5.0(3)N1(1c)",
    "5.0(3)N2(1)",
    "5.0(3)N2(2)",
    "5.0(3)N2(2a)",
    "5.0(3)N2(2b)"
  );
}

if( nx_model =~ "^C?7[0-9]+" ) {
  affected = make_list(
    "4.1.(2)",
    "4.1.(3)",
    "4.1.(4)",
    "4.1.(5)",
    "4.2(3)",
    "4.2(4)",
    "4.2(6)",
    "4.2(8)",
    "4.2.(2a)",
    "5.0(2a)",
    "5.0(3)",
    "5.0(5)",
    "5.1(1)",
    "5.1(1a)",
    "5.1(3)",
    "5.1(4)",
    "5.1(5)",
    "5.1(6)",
    "5.2(1)",
    "5.2(3a)",
    "5.2(4)",
    "5.2(5)",
    "5.2(7)",
    "5.2(9)",
    "6.0(1)",
    "6.0(2)",
    "6.0(3)",
    "6.0(4)",
    "6.1(1)",
    "6.1(2)",
    "6.1(3)",
    "6.1(4)"
  );
}

foreach af ( affected ) {
  if( version == af ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"See advisory" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );

###############################################################################
# OpenVAS Vulnerability Test
#
# Cisco Catalyst 4500 SNMP Polling Denial of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH
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
###############################################################################

CPE = "cpe:/o:cisco:ios";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105380");
  script_version("2022-05-31T13:44:19+0100");
  script_tag(name:"last_modification", value:"2022-05-31 13:44:19 +0100 (Tue, 31 May 2022)");
  script_tag(name:"creation_date", value:"2015-09-21 14:18:25 +0200 (Mon, 21 Sep 2015)");
  script_tag(name:"cvss_base", value:"6.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:C");

  script_cve_id("CVE-2015-0687");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Catalyst 4500 SNMP Polling Denial of Service Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_family("CISCO");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_ssh_cisco_ios_get_version.nasl");
  script_mandatory_keys("cisco_ios/version", "cisco_ios/model");

  script_tag(name:"summary", value:"A vulnerability in the Simple Network Management Protocol (SNMP) code of
  Cisco Catalyst 4500 devices running Cisco IOS Software could allow an authenticated, remote attacker to
  cause a denial of service (DoS) condition.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to an unspecified condition that exists during
  SNMP polling of an affected device that is configured for Virtual Switching System (VSS) with only one
  switch in the VSS cluster.");

  script_tag(name:"impact", value:"An authenticated, remote attacker could exploit this vulnerability to cause
  an affected device to crash, resulting in a DoS condition.");

  script_tag(name:"affected", value:"Cisco IOS Software for Cisco Catalyst 4500 devices running version
  15.1(2)SG4 or 15.2(1.1).");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/Cisco-SA-20150402-CVE-2015-0687");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! model = get_kb_item( "cisco_ios/model" ) )
  exit(0);

if (model !~ "^WS-C45")
  exit( 99 );

if( ! vers = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( vers == "15.1(2)SG4" || vers == "15.2(1.1)" ) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "See advisory");
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

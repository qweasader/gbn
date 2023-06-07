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

CPE = "cpe:/a:cisco:asa";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106394");
  script_version("2022-02-10T15:02:13+0000");
  script_tag(name:"last_modification", value:"2022-02-10 15:02:13 +0000 (Thu, 10 Feb 2022)");
  script_tag(name:"creation_date", value:"2016-11-17 11:43:47 +0700 (Thu, 17 Nov 2016)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");

  script_cve_id("CVE-2016-6461");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco ASA Input Validation File Injection Vulnerability (cisco-sa-20161116-asa)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_asa_version.nasl", "gb_cisco_asa_version_snmp.nasl");
  script_mandatory_keys("cisco_asa/version");

  script_tag(name:"summary", value:"A vulnerability in the HTTP web-based management interface of
  the Cisco Adaptive Security Appliance (ASA) could allow an unauthenticated, remote attacker to
  inject arbitrary XML commands on the affected system.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to improper user input validation. An
  attacker could exploit this vulnerability by crafting XML input into the affected fields of the
  web interface.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to impact the integrity of
  the device data.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161116-asa");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

check_vers = ereg_replace( pattern:"(\(|\))", string:version, replace:"." );
check_vers = ereg_replace( pattern:"\.$", string:check_vers, replace:"" );

affected = make_list(
  '9.1.6.10',
  '9.1.7.4',
  '9.1.7.6',
  '9.1.7.7',
  '9.1.7.9',
  '9.1.7.11',
  '9.1.7.12',
  '9.2.1',
  '9.2.2',
  '9.2.2.4',
  '9.2.2.7',
  '9.2.2.8',
  '9.2.3',
  '9.2.3.3',
  '9.2.3.4',
  '9.2.0.0',
  '9.2.0.104',
  '9.2.3.1',
  '9.2.4',
  '9.2.4.2',
  '9.2.4.4',
  '9.2.4.8',
  '9.2.4.10',
  '9.2.4.13',
  '9.2.4.14',
  '9.2.4.16',
  '9.2.4.17',
  '9.3.1',
  '9.3.1.1',
  '9.3.1.105',
  '9.3.1.50',
  '9.3.2',
  '9.3.2.100',
  '9.3.2.2',
  '9.3.2.243',
  '9.3.3',
  '9.3.3.1',
  '9.3.3.2',
  '9.3.3.5',
  '9.3.3.6',
  '9.3.3.9',
  '9.3.3.10',
  '9.3.3.11',
  '9.3.5',
  '9.4.1',
  '9.4.0.115',
  '9.4.1.1',
  '9.4.1.2',
  '9.4.1.3',
  '9.4.1.5',
  '9.4.2',
  '9.4.2.3',
  '9.4.3',
  '9.4.3.3',
  '9.4.3.4',
  '9.4.3.6',
  '9.4.3.8',
  '9.4.3.11',
  '9.4.3.12',
  '9.4.4',
  '9.5.1',
  '9.5.2',
  '9.5.2.6',
  '9.5.2.10',
  '9.5.2.14' );

foreach af ( affected ) {
  if( check_vers == af ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"See advisory" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );
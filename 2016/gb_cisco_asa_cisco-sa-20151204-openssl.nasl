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
  script_oid("1.3.6.1.4.1.25623.1.0.106284");
  script_version("2022-08-22T10:11:10+0000");
  script_tag(name:"last_modification", value:"2022-08-22 10:11:10 +0000 (Mon, 22 Aug 2022)");
  script_tag(name:"creation_date", value:"2016-09-22 11:38:29 +0700 (Thu, 22 Sep 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-19 11:14:00 +0000 (Fri, 19 Aug 2022)");

  script_cve_id("CVE-2015-3193", "CVE-2015-3194", "CVE-2015-3195", "CVE-2015-3196",
                "CVE-2015-1794");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Adaptive Security Appliance Multiple Vulnerabilities in OpenSSL (cisco-sa-20151204-openssl)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_asa_version.nasl", "gb_cisco_asa_version_snmp.nasl");
  script_mandatory_keys("cisco_asa/version");

  script_tag(name:"summary", value:"On December 3, 2015, the OpenSSL Project released a security
  advisory detailing five vulnerabilities. Cisco Adaptive Security Appliance (ASA) Software
  incorporate a version of the OpenSSL package affected by one or more vulnerabilities that could
  allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151204-openssl");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

check_vers = ereg_replace( pattern:"(\(|\))", string:version, replace:"." );
check_vers = ereg_replace( pattern:"\.$", string:check_vers, replace:"" );

affected = make_list(
  '8.0.1.2',
  '8.0.2',
  '8.0.2.11',
  '8.0.2.15',
  '8.0.3',
  '8.0.3.6',
  '8.0.3.12',
  '8.0.3.19',
  '8.0.4',
  '8.0.4.3',
  '8.0.4.9',
  '8.0.4.16',
  '8.0.4.23',
  '8.0.4.25',
  '8.0.4.28',
  '8.0.4.31',
  '8.0.4.32',
  '8.0.4.33',
  '8.0.5',
  '8.0.5.20',
  '8.0.5.23',
  '8.0.5.25',
  '8.0.5.27',
  '8.0.5.28',
  '8.0.5.31',
  '8.1.1',
  '8.1.1.6',
  '8.1.2',
  '8.1.2.13',
  '8.1.2.15',
  '8.1.2.16',
  '8.1.2.19',
  '8.1.2.23',
  '8.1.2.24',
  '8.1.2.49',
  '8.1.2.50',
  '8.1.2.55',
  '8.1.2.56',
  '8.2.0.45',
  '8.2.1',
  '8.2.1.11',
  '8.2.2',
  '8.2.2.9',
  '8.2.2.10',
  '8.2.2.12',
  '8.2.2.16',
  '8.2.2.17',
  '8.2.3',
  '8.2.4',
  '8.2.4.1',
  '8.2.4.4',
  '8.2.5',
  '8.2.5.13',
  '8.2.5.22',
  '8.2.5.26',
  '8.2.5.33',
  '8.2.5.40',
  '8.2.5.41',
  '8.2.5.46',
  '8.2.5.48',
  '8.2.5.50',
  '8.3.1',
  '8.3.1.1',
  '8.3.1.4',
  '8.3.1.6',
  '8.3.2',
  '8.3.2.4',
  '8.3.2.13',
  '8.3.2.23',
  '8.3.2.25',
  '8.3.2.31',
  '8.3.2.33',
  '8.3.2.34',
  '8.3.2.37',
  '8.3.2.39',
  '8.3.2.40',
  '8.3.2.41',
  '8.4.1',
  '8.4.1.3',
  '8.4.1.11',
  '8.4.2',
  '8.4.2.1',
  '8.4.2.8',
  '8.4.3',
  '8.4.3.8',
  '8.4.3.9',
  '8.4.4',
  '8.4.4.1',
  '8.4.4.3',
  '8.4.4.5',
  '8.4.4.9',
  '8.4.5',
  '8.4.5.6',
  '8.4.6',
  '8.4.7',
  '8.4.7.3',
  '8.4.7.15',
  '8.4.7.22',
  '8.4.7.23',
  '8.5.1',
  '8.5.1.1',
  '8.5.1.6',
  '8.5.1.7',
  '8.5.1.14',
  '8.5.1.17',
  '8.5.1.18',
  '8.5.1.19',
  '8.5.1.21',
  '8.6.1',
  '8.6.1.1',
  '8.6.1.2',
  '8.6.1.5',
  '8.6.1.10',
  '8.6.1.12',
  '8.6.1.13',
  '8.6.1.14',
  '8.7.1',
  '8.7.1.1',
  '8.7.1.3',
  '8.7.1.4',
  '8.7.1.7',
  '8.7.1.8',
  '8.7.1.11',
  '8.7.1.13',
  '9.0.1',
  '9.0.2',
  '9.0.2.10',
  '9.0.3',
  '9.0.3.6',
  '9.0.3.8',
  '9.0.4',
  '9.0.4.1',
  '9.0.4.5',
  '9.0.4.7',
  '9.0.4.17',
  '9.0.4.20',
  '9.0.4.24',
  '9.1.1',
  '9.1.1.4',
  '9.1.2',
  '9.1.2.8',
  '9.1.3',
  '9.1.3.2',
  '9.1.4',
  '9.1.4.5',
  '9.1.5',
  '9.1.5.10',
  '9.1.5.12',
  '9.1.5.15',
  '9.2.1',
  '9.2.2',
  '9.2.2.4',
  '9.2.2.7',
  '9.2.2.8',
  '9.2.3',
  '9.3.1',
  '9.3.1.1',
  '9.3.2' );

foreach af ( affected ) {
  if( check_vers == af ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"See advisory" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );

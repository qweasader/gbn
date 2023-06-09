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

CPE = "cpe:/a:cisco:unified_communications_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105542");
  script_version("2022-03-10T09:57:15+0000");
  script_tag(name:"last_modification", value:"2022-03-10 09:57:15 +0000 (Thu, 10 Mar 2022)");
  script_tag(name:"creation_date", value:"2016-02-12 14:48:29 +0100 (Fri, 12 Feb 2016)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-06 03:06:00 +0000 (Tue, 06 Dec 2016)");

  script_cve_id("CVE-2016-1317");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Unified Communications Manager Information Disclosure Vulnerability (cisco-sa-201600208-ucm)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_cucm_consolidation.nasl");
  script_mandatory_keys("cisco/cucm/detected");

  script_tag(name:"summary", value:"A vulnerability in the web framework of Cisco Unified
  Communications Manager could allow an authenticated, remote attacker to view sensitive data.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to insufficient protection of database
  tables.");

  script_tag(name:"impact", value:"An attacker could exploit this vulnerability by browsing to a
  specific URL. An exploit could allow the attacker to view entity and table names.");

  script_tag(name:"affected", value:"Cisco Unified Communications Manager Release 11.5(0.98000.480).");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-201600208-ucm");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! vers = get_app_version( cpe:CPE, nofork:TRUE, version_regex:"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" ) )
  exit( 0 );

vers = str_replace( string:vers, find:"-", replace:"." );

if( vers == "11.5.0.98000.480" ) {
  report = report_fixed_ver(  installed_version:vers, fixed_version:"See vendor advisory" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

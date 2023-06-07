###############################################################################
# OpenVAS Vulnerability Test
#
# Cisco Unified Computing System Manager Remote Command Execution Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
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

CPE = 'cpe:/a:cisco:unified_computing_system_software';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105526");
  script_cve_id("CVE-2015-6435");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2022-05-17T07:24:43+0000");

  script_name("Cisco Unified Computing System Manager Remote Command Execution Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160120-ucsm");

  script_tag(name:"last_modification", value:"2022-05-17 07:24:43 +0000 (Tue, 17 May 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-30 02:37:00 +0000 (Sat, 30 Jan 2021)");
  script_tag(name:"creation_date", value:"2016-01-25 15:34:07 +0100 (Mon, 25 Jan 2016)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");
  script_family("CISCO");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_ucs_manager_detect.nasl");
  script_mandatory_keys("cisco_ucs_manager/installed");

  script_tag(name:"impact", value:"An exploit could allow the attacker to execute arbitrary commands on the Cisco UCS Manager or the Cisco Firepower 9000 Series appliance.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability is due to unprotected calling of shell commands in the CGI script. An attacker could exploit this vulnerability by sending a crafted HTTP request to the Cisco UCS Manager appliance.");
  script_tag(name:"solution", value:"Updates are available");
  script_tag(name:"summary", value:"A vulnerability in a CGI script in the Cisco Unified Computing System (UCS) Manager and the Cisco Firepower 9000 Series appliance could allow an unauthenticated, remote attacker to execute arbitrary commands on the Cisco UCS Manager or the Cisco Firepower 9000 Series appliance.");
  script_tag(name:"affected", value:"The first fixed releases of Cisco UCS Manager are 2.2(4b), 2.2(5a), and 3.0(2e). Earlier versions of 2.2.x are affected by this vulnerability.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

rep_version = version;
vers = eregmatch( pattern:"^([0-9.]+)\(([^)]+)\)", string:version );

if( isnull( vers[1] ) || isnull( vers[2] ) ) exit( 0 );

major = vers[1];
build = vers[2];

if( version_is_less( version:major, test_version:"2.2" ) ) exit( 99 );

if( major =~ '^2\\.2' )
{
 if( build =~ '^([1-3]+)' ) fix = "2.2(4b)";
 if( build =~ '^(4($|a))' ) fix = "2.2(4b)";

 if( build =~ '^(5($))' ) fix = '2.2(5a)';
 if( build =~ '^(6($))' ) fix = '2.2(6a)';
}

if( major =~ '^3\\.0' )
{
  if( build =~ '^[01]+' )  fix = '3.0(2e)';
  if( build =~ '^2[a-d]+' ) fix = '3.0(2e)';
}

if( major =~ '^3\\.1' )
{
  if( build =~ '^($|[a-d]+)' ) fix = '3.1(e)';
}

if( fix )
{
  report = report_fixed_ver(  installed_version:rep_version, fixed_version:fix );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

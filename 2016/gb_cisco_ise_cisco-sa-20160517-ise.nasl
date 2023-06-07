###############################################################################
# OpenVAS Vulnerability Test
#
# Cisco Identity Services Engine Active Directory Integration Component Remote Denial of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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

CPE = "cpe:/a:cisco:identity_services_engine";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105725");
  script_cve_id("CVE-2016-1402");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("2021-09-20T08:01:57+0000");

  script_name("Cisco Identity Services Engine Active Directory Integration Component Remote Denial of Service Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160517-ise");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to improper handling of password authentication protocol (PAP) authentication
  requests when ISE is configured with an authorization policy based on Active Directory group membership. An attacker could exploit this
  vulnerability by crafting a special but formally correct PAP authentication request that will trigger the issue. An exploit could allow
  the attacker to cause the failures of all subsequent authentication requests for the same Active Directory domain.");

  script_tag(name:"solution", value:"Update to version 1.2.0.899 patch 7 or later. Please see the references for more information.");

  script_tag(name:"summary", value:"A vulnerability in the Active Directory integration component of Cisco Identity Service Engine (ISE)
  could allow an unauthenticated, remote attacker to perform a denial of service attack.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"2021-09-20 08:01:57 +0000 (Mon, 20 Sep 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-01 03:05:00 +0000 (Thu, 01 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-05-18 09:52:59 +0200 (Wed, 18 May 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_ise_version.nasl");
  script_mandatory_keys("cisco_ise/version", "cisco_ise/patch");

  exit(0);
}

include("host_details.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );
if( ! patch = get_kb_item( "cisco_ise/patch" ) ) exit( 0 );

if( version == "1.2.0.899" )
   if( int( patch ) < 7 ) fix = '1.2.0.899 patch 7';

if( fix )
{
  report = 'Installed version: ' + version + '\n';
  if( int( patch ) > 0 ) report +=  'Installed patch:   ' + patch + '\n';
  report +=  'Fixed version:     ' + fix;

  security_message( port:0, data:report);
  exit( 0 );
}

exit( 99 );
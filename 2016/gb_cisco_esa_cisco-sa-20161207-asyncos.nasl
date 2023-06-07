###############################################################################
# OpenVAS Vulnerability Test
#
# Cisco Email Security Appliance AsyncOS Software Update Server Certificate Validation Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
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

CPE = "cpe:/h:cisco:email_security_appliance";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106438");
  script_cve_id("CVE-2016-1411");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_version("2021-09-20T10:01:48+0000");

  script_name("Cisco Email Security Appliance AsyncOS Software Update Server Certificate Validation Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161207-asyncos");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the update functionality of Cisco AsyncOS Software for
Cisco Email Security Appliance (ESA) could allow an unauthenticated, remote attacker to impersonate the update
server.");

  script_tag(name:"insight", value:"The vulnerability is due to a lack of certificate validation during the
HTTPS connection toward the repository from which the update manifests are retrieved.");

  script_tag(name:"impact", value:"An attacker could exploit this vulnerability by performing a man-in-the-middle
attack (such as DNS hijacking) and impersonating the update server.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2021-09-20 10:01:48 +0000 (Mon, 20 Sep 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-15 15:18:00 +0000 (Thu, 15 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-12-08 11:24:12 +0700 (Thu, 08 Dec 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_esa_version.nasl");
  script_mandatory_keys("cisco_esa/installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

affected = make_list(
  '7.5.2-201',
  '7.5.2-HP2-303',
  '7.6.3-025',
  '8.0.1-023',
  '8.5.0-000',
  '8.5.1-021',
  '8.5.0-ER1-198' );

foreach af ( affected )
{
  if( version == af )
  {
    report = report_fixed_ver(  installed_version:version, fixed_version: "See advisory" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );


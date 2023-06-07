###############################################################################
# OpenVAS Vulnerability Test
#
# Cisco WSA Multiple Vulnerabilities 05/16.
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

CPE = "cpe:/h:cisco:web_security_appliance";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105728");
  script_cve_id("CVE-2016-1382", "CVE-2016-1380", "CVE-2016-1381", "CVE-2016-1383");
  script_version("2021-10-07T12:01:23+0000");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2021-10-07 12:01:23 +0000 (Thu, 07 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-01 03:05:00 +0000 (Thu, 01 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-05-23 14:16:36 +0200 (Mon, 23 May 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Cisco WSA Multiple Vulnerabilities 05/16");

  script_tag(name:"summary", value:"Cisco WSA Software is prone to multiple vulnerabilities. CVE-2016-1380 A vulnerability that occurs when parsing an HTTP POST request with Cisco AsyncOS for Cisco Web Security Appliance (WSA) could allow an unauthenticated, remote attacker to cause a denial of service (DoS) vulnerability due to the proxy process becoming unresponsive. CVE-2016-1381 A vulnerability in the cached file-range request functionality of Cisco AsyncOS for Cisco Web Security Appliance (WSA) could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition on an appliance due to the appliance running out of system memory. CVE-2016-1382 A vulnerability in HTTP request parsing in Cisco AsyncOS for the Cisco Web Security Appliance (WSA) could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition when the proxy process unexpectedly restarts. CVE-2016-1383 A vulnerability in Cisco AsyncOS for the Cisco Web Security Appliance (WSA) when the software handles a specific HTTP response code could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition on an appliance because the appliance runs out of system memory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Cisco WSA Software versions prior to 9.0.1-162");

  script_tag(name:"solution", value:"Upgrade to Cisco Web Security Appliance (WSA) software versions 9.0.1-162 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160518-wsa1");
  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160518-wsa2");
  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160518-wsa3");
  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160518-wsa4");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_wsa_version.nasl");
  script_mandatory_keys("cisco_wsa/version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! vers = get_app_version( cpe:CPE ) ) exit( 0 );

version = str_replace( string:vers, find:"-", replace:"." );

if( version_is_less( version:version, test_version:'9.0.1.162' ) )
{
  report = report_fixed_ver( installed_version:vers, fixed_version:"9.0.1-162" );
  security_message( port:0, data:report );
  exit( 0 );
}

###############################################################################
# OpenVAS Vulnerability Test
#
# Cisco IOS and IOS XE Software Internet Key Exchange Version 2 Fragmentation Denial of Service Vulnerability
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

CPE = "cpe:/o:cisco:ios_xe";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105663");
  script_cve_id("CVE-2016-1344");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_version("2021-09-20T13:02:01+0000");

  script_name("Cisco IOS and IOS XE Software Internet Key Exchange Version 2 Fragmentation Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160323-ios-ikev2");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-51122");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityBundle/cisco-sa-20160323-bundle");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"A vulnerability in the Internet Key Exchange (IKE) version 2 (v2)
  fragmentation code of Cisco IOS and IOS XE Software could allow an unauthenticated,
  remote attacker to cause a reload of the affected system.

  The vulnerability is due to an improper handling of crafted, fragmented IKEv2 packets. An attacker could exploit this vulnerability by
  sending crafted UDP packets to the affected system. An exploit
  could allow the attacker to cause a reload of the affected system.

  Note: Only traffic directed to the affected system can
  be used to exploit this vulnerability. This vulnerability can be triggered by IPv4 and
  IPv6 traffic.

  Cisco has released software updates that address this vulnerability.
  This advisory is available at the references.

  This advisory is part of the March 23, 2016, release of the Cisco IOS and IOS XE Software Security Advisory Bundled Publication,
  which includes six Cisco Security Advisories that describe six vulnerabilities. All the vulnerabilities have a Security Impact
  Rating of `High.` For a complete list of advisories and links to them, see Cisco Event Response: Semiannual Cisco IOS and IOS XE
  Software Security Advisory Bundled Publication.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2021-09-20 13:02:01 +0000 (Mon, 20 Sep 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-05-12 01:29:00 +0000 (Fri, 12 May 2017)");
  script_tag(name:"creation_date", value:"2016-05-09 17:34:44 +0200 (Mon, 09 May 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_ios_xe_consolidation.nasl");
  script_mandatory_keys("cisco/ios_xe/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

affected = make_list(
  '3.8.0E',
  '3.8.1E',
  '3.3.0S',
  '3.3.1S',
  '3.3.2S',
  '3.3.0SG',
  '3.3.1SG',
  '3.3.2SG',
  '3.3.0XO',
  '3.3.1XO',
  '3.3.2XO',
  '3.4.0S',
  '3.4.0a.S',
  '3.4.1S',
  '3.4.2S',
  '3.4.3S',
  '3.4.4S',
  '3.4.5S',
  '3.4.6S',
  '3.4.0SG',
  '3.4.1SG',
  '3.4.2SG',
  '3.4.3SG',
  '3.4.4SG',
  '3.4.5SG',
  '3.4.6SG',
  '3.4.7SG',
  '3.5.0E',
  '3.5.1E',
  '3.5.2E',
  '3.5.3E',
  '3.5.0S',
  '3.5.1S',
  '3.5.2S',
  '3.6.0E',
  '3.6.1E',
  '3.6.2a.E',
  '3.6.2E',
  '3.6.3E',
  '3.6.0S',
  '3.6.1S',
  '3.6.2S',
  '3.7.3E',
  '3.7.0E',
  '3.7.1E',
  '3.7.2E',
  '3.7.0S',
  '3.7.1S',
  '3.7.2S',
  '3.7.2t.S',
  '3.7.3S',
  '3.7.4S',
  '3.7.4a.S',
  '3.7.5S',
  '3.7.6S',
  '3.7.7S',
  '3.8.0S',
  '3.8.1S',
  '3.8.2S',
  '3.9.0S',
  '3.9.0a.S',
  '3.9.1S',
  '3.9.1a.S',
  '3.9.2S',
  '3.10.0S',
  '3.10.1S',
  '3.10.1xb.S',
  '3.10.2S',
  '3.10.3S',
  '3.10.4S',
  '3.10.5S',
  '3.10.6S',
  '3.11.0S',
  '3.11.1S',
  '3.11.2S',
  '3.11.3S',
  '3.11.4S',
  '3.12.0S',
  '3.12.1S',
  '3.12.4S',
  '3.12.2S',
  '3.12.3S',
  '3.13.2a.S',
  '3.13.0S',
  '3.13.0a.S',
  '3.13.1S',
  '3.13.2S',
  '3.13.3S',
  '3.13.4S',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.15.1c.S',
  '3.15.0S',
  '3.15.1S',
  '3.15.2S',
  '3.17.0S',
  '3.16.0S',
  '3.16.0c.S',
  '3.16.1S',
  '3.16.1a.S' );

foreach af ( affected )
{
  if( version == af )
  {
    report = report_fixed_ver(installed_version:version, fixed_version:"See advisory" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );

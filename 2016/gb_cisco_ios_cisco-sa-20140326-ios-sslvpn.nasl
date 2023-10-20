# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:cisco:ios";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105648");
  script_cve_id("CVE-2014-2112");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("2023-07-21T05:05:22+0000");

  script_name("Cisco IOS Software SSL VPN Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140326-ios-sslvpn");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityBundle/cisco-sa-20140326-bundle");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=33350");
  script_xref(name:"URL", value:"http://www.cisco.com/web/about/security/intelligence/Cisco_ERP_mar14.html");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"A vulnerability in the Secure Sockets Layer (SSL) VPN subsystem of Cisco IOS Software could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition.

The vulnerability is due to a failure to process certain types of HTTP requests. To exploit the vulnerability, an attacker could submit crafted requests designed to consume memory to an affected device. An exploit could allow the attacker to consume and fragment memory on the affected device. This may cause reduced performance, a failure of certain processes, or a restart of the affected device.

Cisco has released software updates that address this vulnerability. There are no workarounds to mitigate this vulnerability.

Note: The March 26, 2014, Cisco IOS Software Security Advisory bundled publication includes six Cisco Security Advisories. All advisories address vulnerabilities in Cisco IOS Software. Each Cisco IOS Software Security Advisory lists the Cisco IOS Software releases that correct the vulnerability or vulnerabilities detailed in the advisory as well as the Cisco IOS Software releases that correct all Cisco IOS Software vulnerabilities in the March 2014 bundled publication.

Individual publication links are in Cisco Event Response: Semiannual Cisco IOS Software Security Advisory Bundled Publication at the referenced links.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-05-04 18:46:26 +0200 (Wed, 04 May 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_ssh_cisco_ios_get_version.nasl");
  script_mandatory_keys("cisco_ios/version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

affected = make_list(
  '15.1(2)GC',
  '15.1(2)GC1',
  '15.1(2)GC2',
  '15.1(4)GC',
  '15.1(4)GC1',
  '15.1(4)GC2',
  '15.1(4)M',
  '15.1(4)M0a',
  '15.1(4)M0b',
  '15.1(4)M1',
  '15.1(4)M2',
  '15.1(4)M3',
  '15.1(4)M3a',
  '15.1(4)M4',
  '15.1(4)M5',
  '15.1(4)M6',
  '15.1(2)T',
  '15.1(2)T0a',
  '15.1(2)T1',
  '15.1(2)T2',
  '15.1(2)T2a',
  '15.1(2)T3',
  '15.1(2)T4',
  '15.1(2)T5',
  '15.1(3)T',
  '15.1(3)T1',
  '15.1(3)T2',
  '15.1(3)T3',
  '15.1(3)T4',
  '15.1(4)XB8',
  '15.1(4)XB8a',
  '15.2(1)GC',
  '15.2(1)GC1',
  '15.2(1)GC2',
  '15.2(2)GC',
  '15.2(3)GC',
  '15.2(3)GC1',
  '15.2(4)GC',
  '15.2(3)GCA',
  '15.2(3)GCA1',
  '15.2(4)M',
  '15.2(4)M1',
  '15.2(4)M2',
  '15.2(4)M3',
  '15.2(4)M4',
  '15.2(4)M5',
  '15.2(1)T',
  '15.2(1)T1',
  '15.2(1)T2',
  '15.2(1)T3',
  '15.2(1)T3a',
  '15.2(1)T4',
  '15.2(2)T',
  '15.2(2)T1',
  '15.2(2)T2',
  '15.2(2)T3',
  '15.2(2)T4',
  '15.2(3)T',
  '15.2(3)T1',
  '15.2(3)T2',
  '15.2(3)T3',
  '15.2(3)T4',
  '15.2(3)XA',
  '15.2(4)XB10',
  '15.3(3)M',
  '15.3(3)M1',
  '15.3(1)T',
  '15.3(1)T1',
  '15.3(1)T2',
  '15.3(1)T3',
  '15.3(2)T',
  '15.3(2)T1',
  '15.3(2)T2',
  '15.4(1)CG',
  '15.4(1)S',
  '15.4(1)T' );

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


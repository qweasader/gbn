# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:cisco:ios";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105637");
  script_cve_id("CVE-2011-3271");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2023-07-21T05:05:22+0000");

  script_name("Cisco IOS Software Smart Install Remote Code Execution Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20110928-smart-install");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityBundle/cisco-sa-20110928-bundle");
  script_xref(name:"URL", value:"http://www.cisco.com/web/about/security/intelligence/Cisco_ERP_sep11.html");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"A vulnerability exists in the Smart Install feature of Cisco Catalyst
  Switches running Cisco IOS Software that could allow an
  unauthenticated, remote attacker to perform remote code execution on the
  affected device.

  Cisco has released software updates that address this vulnerability.
  There are no workarounds available to mitigate this vulnerability other than disabling the Smart Install feature.

  Note: The September 28, 2011, Cisco IOS Software Security Advisory bundled publication includes ten Cisco Security Advisories.
  Nine of the advisories address vulnerabilities in Cisco IOS Software, and one advisory addresses a vulnerability in Cisco Unified Communications Manager.
  Each advisory lists the Cisco IOS Software releases that correct the vulnerability or vulnerabilities detailed
  in the advisory as well as the Cisco IOS Software releases that correct all vulnerabilities in the September 2011 Bundled Publication.

  Individual publication links are in `Cisco Event Response: Semiannual Cisco IOS Software Security Advisory Bundled Publication` at the references.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-05-03 19:23:33 +0200 (Tue, 03 May 2016)");
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
  '12.2(52)EX',
  '12.2(52)EX1',
  '12.2(55)EX',
  '12.2(55)EX1',
  '12.2(55)EX2',
  '12.2(53)EY',
  '12.2(55)EY',
  '12.2(55)EZ',
  '12.2(52)SE',
  '12.2(53)SE',
  '12.2(53)SE1',
  '12.2(53)SE2',
  '12.2(55)SE',
  '12.2(55)SE1',
  '12.2(55)SE2',
  '15.1(4)M',
  '15.1(4)M1',
  '15.1(3)T',
  '15.1(3)T1' );

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


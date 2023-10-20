# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:cisco:ios_xe";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106317");
  script_cve_id("CVE-2016-6393");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_version("2023-07-20T05:05:17+0000");

  script_name("Cisco IOS XE Software AAA Login Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160928-aaados");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the Authentication, Authorization, and Accounting (AAA)
service for remote Secure Shell Host (SSH) connections to the device for Cisco IOS XE Software could allow an
unauthenticated, remote attacker to cause the vulnerable device to reload.");

  script_tag(name:"insight", value:"The vulnerability is due to an error log message when a remote SSH
connection to the device fails AAA authentication. An attacker could exploit this vulnerability by attempting
to authenticate to the targeted device.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to cause a denial of service (DoS)
condition.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-11 17:24:00 +0000 (Mon, 11 May 2020)");
  script_tag(name:"creation_date", value:"2016-09-29 16:00:26 +0700 (Thu, 29 Sep 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_cisco_ios_xe_consolidation.nasl");
  script_mandatory_keys("cisco/ios_xe/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

affected = make_list(
  '16.2.1',
  '3.18.0a.S',
  '3.18.0S',
  '3.8.0E',
  '3.8.1E',
  '3.8.0EX',
  '99.9.0Z',
  '2.1.0',
  '2.1.1',
  '2.1.2',
  '2.1.3',
  '2.2.0',
  '2.2.1',
  '2.2.2',
  '2.2.3',
  '2.3.1',
  '2.3.0',
  '2.3.0t',
  '2.3.1t',
  '2.3.2',
  '2.4.0',
  '2.4.1',
  '2.4.2',
  '2.4.3',
  '2.5.0',
  '2.5.1',
  '2.5.2',
  '2.6.0',
  '2.6.1',
  '2.6.2',
  '2.6.2a',
  '3.1.3a.S',
  '3.1.0S',
  '3.1.1S',
  '3.1.2S',
  '3.1.3S',
  '3.1.4S',
  '3.1.4a.S',
  '3.1.5S',
  '3.1.6S',
  '3.1.0SG',
  '3.1.1SG',
  '3.2.0S',
  '3.2.1S',
  '3.2.2S',
  '3.2.3S',
  '3.2.0SE',
  '3.2.1SE',
  '3.2.2SE',
  '3.2.3SE',
  '3.2.0SG',
  '3.2.1SG',
  '3.2.2SG',
  '3.2.3SG',
  '3.2.4SG',
  '3.2.5SG',
  '3.2.6SG',
  '3.2.7SG',
  '3.2.8SG',
  '3.2.9SG',
  '3.2.10SG',
  '3.2.0XO',
  '3.2.1XO',
  '3.3.0S',
  '3.3.1S',
  '3.3.2S',
  '3.3.0SE',
  '3.3.1SE',
  '3.3.2SE',
  '3.3.3SE',
  '3.3.4SE',
  '3.3.5SE',
  '3.3.0SG',
  '3.3.1SG',
  '3.3.2SG',
  '3.3.0SQ',
  '3.3.1SQ',
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
  '3.4.0SQ',
  '3.4.1SQ',
  '3.5.0E',
  '3.5.1E',
  '3.5.2E',
  '3.5.3E',
  '3.5.0S',
  '3.5.1S',
  '3.5.2S',
  '3.5.1SQ',
  '3.5.2SQ',
  '3.5.0SQ',
  '3.6.4E',
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
  '3.7.0b.S',
  '3.7.0xa.S',
  '3.7.1S',
  '3.7.1a.S',
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
  '3.10.0a.S',
  '3.10.1S',
  '3.10.1xb.S',
  '3.10.2S',
  '3.10.2t.S',
  '3.10.3S',
  '3.10.4S',
  '3.10.5S',
  '3.10.6S',
  '3.10.7S',
  '3.10.01S',
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
  '3.13.5a.S',
  '3.13.5S',
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
  '3.15.3S',
  '3.15.0S',
  '3.15.1S',
  '3.15.2S',
  '3.17.1a.S',
  '3.17.0S',
  '3.17.1S',
  '16.1.1',
  '16.1.2',
  '3.16.2b.S',
  '3.16.0S',
  '3.16.0c.S',
  '3.16.1S',
  '3.16.1a.S',
  '3.16.2S',
  '3.16.2a.S' );

foreach af ( affected )
{
  if( version == af )
  {
    report = report_fixed_ver( installed_version:version, fixed_version:"See advisory" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );

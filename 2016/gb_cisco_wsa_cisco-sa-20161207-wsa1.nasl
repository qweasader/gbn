# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:cisco:web_security_appliance";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106456");
  script_cve_id("CVE-2016-9212");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_version("2023-07-21T05:05:22+0000");

  script_name("Cisco Web Security Appliance Drop Decrypt Policy Bypass Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161207-wsa1");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the Decrypt for End-User Notification configuration
parameter of Cisco AsyncOS Software for Cisco Web Security Appliances could allow an unauthenticated, remote
attacker to connect to a secure website over Secure Sockets Layer (SSL) or Transport Layer Security (TLS), even
if the WSA is configured to block connections to the website.");

  script_tag(name:"insight", value:"The vulnerability is due to incomplete input validation of HTTP headers. An
attacker could exploit this vulnerability by sending a crafted HTTP request through an affected device.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to connect to a website that
should be blocked.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-22 21:12:00 +0000 (Thu, 22 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-12-08 11:24:12 +0700 (Thu, 08 Dec 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_cisco_wsa_version.nasl");
  script_mandatory_keys("cisco_wsa/installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

affected = make_list(
  '9.0.1-162',
  '9.1.1-074',
  '9.1.2-039',
  '10.1.1-235',
  '10.5.1-296',
  '11.0.0-641' );

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

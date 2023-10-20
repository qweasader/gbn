# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:prime_collaboration_provisioning";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107074");
  script_cve_id("CVE-2016-6451");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_version("2023-07-20T05:05:17+0000");

  script_name("Cisco Prime Collaboration Provisioning Cross-Site Scripting Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161026-pcp");

  script_tag(name:"impact", value:"An attacker could exploit this vulnerability by convincing the user to access
a malicious link or by intercepting the user request and injecting malicious code. An exploit could allow the
attacker to execute arbitrary script code in the context of the affected site or allow the attacker to access
sensitive browser-based information.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to insufficient input validation of some parameters
passed to the web server.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"Multiple vulnerabilities in the web framework code of the Cisco Prime
Collaboration Provisioning could allow an unauthenticated, remote attacker to conduct a cross-site scripting (XSS)
attack against the user of the web interface of the affected system.");

  script_tag(name:"affected", value:"Cisco Prime Collaboration Provisioning version 10.6.0 is vulnerable.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-29 01:34:00 +0000 (Sat, 29 Jul 2017)");
  script_tag(name:"creation_date", value:"2016-10-28 15:41:14 +0200 (Fri, 28 Oct 2016)");

  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_cisco_pcp_version.nasl");
  script_mandatory_keys("cisco_pcp/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! vers = get_app_version( cpe:CPE ) ) exit( 0 );

v = split( vers, sep:".", keep:FALSE );
if( max_index( v ) < 4 ) exit( 0 );

if ( vers =~ "^10\.6\.0" ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See advisory" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

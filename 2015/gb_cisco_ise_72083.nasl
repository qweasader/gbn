# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:identity_services_engine";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105471");
  script_cve_id("CVE-2014-8022");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_version("2023-07-25T05:05:58+0000");

  script_name("Cisco Identity Services Engine Multiple Cross Site Scripting Vulnerabilities");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=37045");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72083");

  script_tag(name:"impact", value:"An unauthenticated, remote attacker could exploit this vulnerability to execute arbitrary script or HTML code in the user's browser in the security context of the affected application. This action could allow the attacker to steal sensitive browser-based information, including authentication cookies and recently submitted data, or to take actions on the site as the affected user.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability is due to insufficient input validation on several web pages. An attacker could exploit this vulnerability by persuading a user to access a malicious link.");
  script_tag(name:"solution", value:"See vendor advisory for a solution");
  script_tag(name:"summary", value:"A vulnerability in the web framework of Cisco Identity Services Engine could allow an unauthenticated, remote attacker to conduct a cross-site scripting (XSS) attack against a user of the web interface on the affected system.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-12-01 15:23:53 +0100 (Tue, 01 Dec 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_cisco_ise_version.nasl");
  script_mandatory_keys("cisco_ise/version");

  exit(0);
}

include("host_details.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

affected = make_list( "1.2.0.915","1.2.1.198","1.3.0.862","1.3.0.876","1.2.0.913","1.4.0.181","1.4.0.904" );

foreach a ( affected )
{
  if( a == version )
  {
    report = 'Installed version: ' + version + '\n' +
             'Fixed version:     See vendor advisory';
    security_message( port:0, data:report);
    exit( 0 );
  }
}

exit( 99 );

# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:prime_infrastructure";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106167");
  script_cve_id("CVE-2016-1474");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_version("2023-07-20T05:05:17+0000");

  script_name("Cisco Prime Infrastructure Cross-Frame Scripting Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160803-cpi");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Upgrade to Cisco Prime Infrastructure
 version 3.1(1) or later.");
  script_tag(name:"summary", value:"A vulnerability in the web interface of Cisco Prime Infrastructure
could allow an unauthenticated, remote attacker to execute a cross-frame scripting (XFS) attack.

This vulnerability is due to insufficient HTML iframe protection. An attacker could exploit this vulnerability
by directing a user to an attacker-controlled web page that contains a malicious HTML iframe. An exploit could
allow the attacker to conduct clickjacking or other client-side browser attacks.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-16 01:29:00 +0000 (Wed, 16 Aug 2017)");
  script_tag(name:"creation_date", value:"2016-08-04 12:28:14 +0700 (Thu, 04 Aug 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_cisco_pis_version.nasl");
  script_mandatory_keys("cisco_pis/version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

affected = make_list(
  '2.2.2' );

foreach af ( affected )
{
  if( version == af )
  {
    report = report_fixed_ver(installed_version:version, fixed_version: "3.1(1)");
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );


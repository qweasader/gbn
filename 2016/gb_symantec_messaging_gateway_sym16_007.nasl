# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:symantec:messaging_gateway";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105722");
  script_version("2023-07-21T05:05:22+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2014-0160");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-15 13:29:00 +0000 (Thu, 15 Oct 2020)");
  script_tag(name:"creation_date", value:"2016-05-17 13:54:13 +0200 (Tue, 17 May 2016)");

  script_name("Symantec Messaging Gateway 10.6.x ACE Library Static Link to Vulnerable SSL Version (SYM16-007)");

  script_tag(name:"summary", value:"Symantec Messaging Gateway (SMG) Appliance 10.6.x management console was
susceptible to potential unauthorized loss of privileged information due to an inadvertent static link of an
updated component library to a version of SSL susceptible to the Heartbleed vulnerability (CVE-2014-0160).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Symantec became aware of a recently updated ACE library shipped in SMG 10.6.x
that was statically linked inadvertently to a version of SSL susceptible to CVE-2014-0160, Heartbleed vice
dynamically linked to the non-vulnerable SSL version in the shipping OS of the Appliance.");

  script_tag(name:"affected", value:"SMG 10.x, 10.6.1 and earlier.");

  script_tag(name:"solution", value:"Update to SMG 10.6.1-3 or newer.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2016&suid=20160512_00");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66690");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_symantec_messaging_gateway_detect.nasl");
  script_mandatory_keys("symantec_smg/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

if( version_is_less( version:version, test_version:"10.6.1" ) ) VULN = TRUE;

if( version == "10.6.1" )
{
  if( patch = get_kb_item( "symantec_smg/patch" ) )
    if( int( patch ) < 3 ) VULN = TRUE;
}

if( VULN )
{
  if( patch ) version = version + " Patch " + patch;
  report = report_fixed_ver( installed_version:version, fixed_version:'10.6.1 Patch 3' );
  security_message( port:0, data:report );
  exit(0);
}


exit( 99 );


# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113261");
  script_version("2023-07-20T05:05:18+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:18 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-08-31 12:56:57 +0200 (Fri, 31 Aug 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-08 13:19:00 +0000 (Thu, 08 Nov 2018)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-15596");

  script_name("myBB <= 1.8.17 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_mybb_detect.nasl");
  script_mandatory_keys("MyBB/installed");

  script_tag(name:"summary", value:"myBB is prone to a Cross-Site-Scripting (XSS) Vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The thread titles are not sanitized, resulting in XSS.");
  script_tag(name:"impact", value:"Successful authentication would allow an authenticated attacker
  to inject arbitrary code into the website.");
  script_tag(name:"affected", value:"mybb through version 1.8.17.");
  script_tag(name:"solution", value:"Update to version 1.8.18");

  script_xref(name:"URL", value:"https://blog.mybb.com/2018/08/22/mybb-1-8-18-released-security-maintenance-release/");

  exit(0);
}

CPE = "cpe:/a:mybb:mybb";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port, nofork: TRUE ) ) exit( 0 );

if( version_is_less( version: version, test_version: "1.8.18" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.8.18" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

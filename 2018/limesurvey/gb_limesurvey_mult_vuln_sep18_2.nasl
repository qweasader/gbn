# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113263");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-09-05 11:15:05 +0200 (Wed, 05 Sep 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-09 17:53:00 +0000 (Fri, 09 Nov 2018)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-16397", "CVE-2018-17003");

  script_name("LimeSurvey <= 3.14.7 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_limesurvey_detect.nasl");
  script_mandatory_keys("limesurvey/installed");

  script_tag(name:"summary", value:"LimeSurvey is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - An admin user can leverage a file upload question to read an arbitrary file

  - An authenticated stored XSS vulnerability can be exploited via /index.php?r=admin/survey/sa/insert");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"LimeSurvey through version 3.14.7.");

  script_tag(name:"solution", value:"Update to version 3.14.8 or later.");

  script_xref(name:"URL", value:"https://github.com/LimeSurvey/LimeSurvey/blob/3be9b41e76826b57f5860d18d93b23f47d59d2e4/docs/release_notes.txt#L51");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/149435/LimeSurvey-3.14.7-Cross-Site-Scripting.html");

  exit(0);
}

CPE = "cpe:/a:limesurvey:limesurvey";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less( version: version, test_version: "3.14.8" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.14.8" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

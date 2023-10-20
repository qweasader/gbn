# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113164");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-04-19 15:06:33 +0200 (Thu, 19 Apr 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-05-18 17:08:00 +0000 (Fri, 18 May 2018)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2014-1686");

  script_name("MediaWiki 1.18.0 Installation Path Disclosure Vulnerability (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_mediawiki_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mediawiki/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"MediaWiki allows remote attackers to obtain the installation path via vectors related to thumbnail creation.");
  script_tag(name:"vuldetect", value:"The script checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"MediaWiki through version 1.18.0");
  script_tag(name:"solution", value:"Update to MedaiWiki 1.27.4 or above.");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Mar/102");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66141");
  script_xref(name:"URL", value:"https://www.mediawiki.org/wiki/Download");

  exit(0);
}

CPE = "cpe:/a:mediawiki:mediawiki";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less_equal( version: version, test_version: "1.18.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.27.4" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

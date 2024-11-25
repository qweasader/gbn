# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:roundcube:webmail";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114630");
  script_version("2024-10-25T15:39:56+0000");
  script_tag(name:"last_modification", value:"2024-10-25 15:39:56 +0000 (Fri, 25 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-05-23 14:46:53 +0000 (Thu, 23 May 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-25 13:56:29 +0000 (Fri, 25 Oct 2024)");

  script_cve_id("CVE-2024-37383", "CVE-2024-37384");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Roundcube Webmail < 1.5.7, 1.6.x < 1.6.7 Multiple Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_roundcube_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("roundcube/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Roundcube Webmail is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2024-37383: Cross-site scripting (XSS) vulnerability in handling SVG animate attributes

  - CVE-2024-37384: XSS vulnerability in handling list columns from user preferences");

  script_tag(name:"affected", value:"Roundcube Webmail versions prior to 1.5.7 and 1.6.x
  prior to 1.6.7.");

  script_tag(name:"solution", value:"Update to version 1.5.7, 1.6.7 or later.");

  script_xref(name:"URL", value:"https://roundcube.net/news/2024/05/19/security-updates-1.6.7-and-1.5.7");
  script_xref(name:"URL", value:"https://github.com/roundcube/roundcubemail/releases/tag/1.6.7");
  script_xref(name:"URL", value:"https://github.com/roundcube/roundcubemail/releases/tag/1.5.7");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2290826");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2290830");
  script_xref(name:"URL", value:"https://global.ptsecurity.com/analytics/pt-esc-threat-intelligence/fake-attachment-roundcube-mail-server-attacks-exploit-cve-2024-37383-vulnerability");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"1.5.7" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"1.5.7", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"1.6", test_version_up:"1.6.7" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"1.6.7", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:xwiki:xwiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124404");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-08-18 08:15:22 +0000 (Fri, 18 Aug 2023)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-28 17:23:00 +0000 (Fri, 28 Apr 2023)");

  script_cve_id("CVE-2023-29515");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("XWiki 4.0-milestone-2 < 13.10.11, 14.0-rc-1 < 14.4.8, 14.5 < 14.10.1 XSS Vulnerability (GHSA-44h9-xxvx-pg6x)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_xwiki_enterprise_detect.nasl");
  script_mandatory_keys("xwiki/detected");

  script_tag(name:"summary", value:"Xwiki is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Any user who can create a space can become admin of that space
  through App Within Minutes. The admin right implies the script right and thus allows JavaScript
  injection. The vulnerability can be exploited by creating an app in App Within Minutes. If the
  button should be disabled because the user doesn't have global edit right, the app can also be
  created by directly opening /xwiki/bin/view/AppWithinMinutes/CreateApplication?wizard=true on the
  XWiki installation.");

  script_tag(name:"affected", value:"XWiki version 4.0-milestone-2 prior to 13.10.11, 14.0-rc-1 prior to
  14.4.8 and 14.5 prior to 14.10.1.");

  script_tag(name:"solution", value:"Update to version 13.10.11, 14.4.8, 14.10.1 or later.");

  script_xref(name:"URL", value:"https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-44h9-xxvx-pg6x");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if ( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range_exclusive( version:version, test_version_lo:"4.0-milestone-2", test_version_up:"13.10.11" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"13.10.11", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"14.0-rc-1", test_version_up:"14.4.8" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"14.4.8", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"14.5", test_version_up:"14.10.1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"14.10.1", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:xwiki:xwiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124633");
  script_version("2024-04-23T05:05:27+0000");
  script_tag(name:"last_modification", value:"2024-04-23 05:05:27 +0000 (Tue, 23 Apr 2024)");
  script_tag(name:"creation_date", value:"2024-04-15 05:30:39 +0000 (Mon, 15 Apr 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2024-31983");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("XWiki 4.3-milestone-2 < 14.10.20, 15.0-rc-1 < 15.5.4, 15.6-rc-1 < 15.10-rc-1 RCE Vulnerability (GHSA-xxp2-9c9g-7wmj)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_xwiki_enterprise_detect.nasl");
  script_mandatory_keys("xwiki/detected");

  script_tag(name:"summary", value:"Xwiki is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"In multilingual wikis, translations can be edited by any user
  who has edit right, circumventing the rights that are normally required for authoring
  translations script right for user-scope translations, wiki admin for translations on the wiki.
  This can be exploited for remote code execution if the translation value is not properly escaped
  where it is used.");

  script_tag(name:"affected", value:"XWiki version 4.3-milestone-2 prior to 14.10.20, 15.0-rc-1
  prior to 15.5.4 and 15.6-rc-1 prior to 15.10-rc-1.");

  script_tag(name:"solution", value:"Update to version 14.10.20, 15.5.4, 15.10-rc-1 or later.");

  script_xref(name:"URL", value:"https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-xxp2-9c9g-7wmj");

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

if( version_in_range_exclusive( version:version, test_version_lo:"4.3-milestone-2", test_version_up:"14.10.20" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"14.10.20", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"15.0-rc-1", test_version_up:"15.5.4" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"15.5.4", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"15.6-rc-1", test_version_up:"15.10-rc-1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"15.10-rc-1", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:xwiki:xwiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124360");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-07-13 09:03:39 +0000 (Thu, 13 Jul 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-25 18:26:00 +0000 (Tue, 25 Apr 2023)");

  script_cve_id("CVE-2023-29201");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("XWiki 4.2-milestone-1 < 14.6-rc-1 XSS Vulnerability (GHSA-m3jr-cvhj-f35j)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_xwiki_enterprise_detect.nasl");
  script_mandatory_keys("xwiki/detected");

  script_tag(name:"summary", value:"Xwiki is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The 'restricted' mode of the HTML cleaner in XWiki, introduced,
  only escaped <script> and <style>-tags but neither attributes that can be used to inject scripts
  nor other dangerous HTML tags like <iframe>. As a consequence, any code relying on this
  'restricted' mode for security is vulnerable to JavaScript injection");

  script_tag(name:"affected", value:"XWiki version 4.2-milestone-1 prior to 14.6-rc-1.");

  script_tag(name:"solution", value:"Update to version 14.6-rc-1 or later.");

  script_xref(name:"URL", value:"https://github.com/xwiki/xwiki-commons/security/advisories/GHSA-m3jr-cvhj-f35j");

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

if( version_in_range_exclusive( version:version, test_version_lo:"4.2-milestone-1", test_version_up:"14.6-rc-1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"14.6-rc-1", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

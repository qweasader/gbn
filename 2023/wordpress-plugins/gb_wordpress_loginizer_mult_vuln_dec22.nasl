# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:loginizer:loginizer";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.127463");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-06-07 08:42:28 +0000 (Wed, 07 Jun 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-26 14:02:00 +0000 (Fri, 26 May 2023)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2022-45079", "CVE-2022-45084");

  script_name("WordPress Loginizer Plugin < 1.7.6 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/loginizer/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Loginizer' is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-45079: Cross-site request forgery (CSRF)

  - CVE-2022-45084: Unauthenticated reflected cross-site scripting (XSS)");

  script_tag(name:"affected", value:"WordPress Loginizer plugin prior to version 1.7.6.");

  script_tag(name:"solution", value:"Update to version 1.7.6 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/loginizer/wordpress-loginizer-plugin-1-7-5-cross-site-request-forgery-csrf-vulnerability");
  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/loginizer/wordpress-loginizer-plugin-1-7-5-unauth-reflected-cross-site-scripting-xss-vulnerability");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "1.7.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.7.6", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

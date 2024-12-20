# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ultimatemember:ultimate_member";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127043");
  script_version("2024-11-01T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"creation_date", value:"2022-06-14 13:36:14 +0000 (Tue, 14 Jun 2022)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-17 23:18:00 +0000 (Fri, 17 Jun 2022)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2022-1208");

  script_name("WordPress Ultimate Member Plugin <= 2.3.2 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/ultimate-member/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Ultimate Member' is prone to a
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This exist due to insufficient input sanitization
  and output escaping on the 'frameid' parameter found in the
  ~/src/Package/views/shortcode-iframe.php file.");

  script_tag(name:"affected", value:"WordPress Ultimate Member plugin version 2.3.2 and prior.");

  script_tag(name:"solution", value:"Update to version 2.4.0 or later.");

  script_xref(name:"URL", value:"https://github.com/H4de5-7/vulnerabilities/blob/main/Ultimate%20Member%20%3C%3D%202.3.1%20-%20Stored%20Cross-Site%20Scripting.md");
  script_xref(name:"URL", value:"https://www.wordfence.com/vulnerability-advisories/#CVE-2022-1208");
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

if( version_is_less_equal( version: version, test_version: "2.3.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.4.0", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );

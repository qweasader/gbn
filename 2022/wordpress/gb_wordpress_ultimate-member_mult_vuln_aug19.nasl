# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ultimatemember:ultimate_member";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127079");
  script_version("2024-11-01T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"creation_date", value:"2022-07-12 13:20:16 +0000 (Tue, 12 Jul 2022)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-14 20:03:00 +0000 (Wed, 14 Aug 2019)");

  script_cve_id("CVE-2019-14946", "CVE-2019-14947");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Ultimate Member Plugin < 2.0.52 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/ultimate-member/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Ultimate Member' is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2019-14946: Cross-site scripting (XSS) related to UM Roles create and edit operations

  - CVE-2019-14947: Cross-site scripting (XSS) during an account upgrade");

  script_tag(name:"affected", value:"WordPress Ultimate Member plugin prior to version 2.0.52.");

  script_tag(name:"solution", value:"Update to version 2.0.52 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/9449");

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

if( version_is_less( version: version, test_version: "2.0.52" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.0.52", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );

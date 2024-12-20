# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wp-slimstat:slimstat_analytics";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124329");
  script_version("2024-11-01T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"creation_date", value:"2023-05-26 09:15:00 +0000 (Fri, 26 May 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-14 15:36:00 +0000 (Tue, 14 Nov 2023)");

  script_cve_id("CVE-2022-45366", "CVE-2022-45373");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Slimstat Analytics Plugin < 5.0.5 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-slimstat/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Slimstat Analytics' is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-45366: This could allow a malicious actor to inject malicious scripts,
  such as redirects, advertisements, and other HTML payloads into your website which will be
  executed when guests visit your site.

  - CVE-2022-45373: Improper neutralization of special elements used in an SQL Command allows to an
  SQL Injection (SQLi).");

  script_tag(name:"affected", value:"WordPress Slimstat Analytics plugin prior to version 5.0.5.");

  script_tag(name:"solution", value:"Update to version 5.0.5 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/wp-slimstat/wordpress-slimstat-analytics-plugin-5-0-4-reflected-cross-site-scripting-xss-vulnerability");
  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/wp-slimstat/wordpress-slimstat-analytics-plugin-5-0-4-sql-injection-sqli-vulnerability");

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

if( version_is_less( version: version, test_version: "5.0.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.0.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );

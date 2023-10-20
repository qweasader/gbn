# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wp-slimstat:slimstat_analytics";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127567");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-02 06:40:00 +0000 (Mon, 02 Oct 2023)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-28 20:28:00 +0000 (Thu, 28 Sep 2023)");

  script_cve_id("CVE-2023-40676");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Slimstat Analytics Plugin < 5.0.9 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-slimstat/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Slimstat Analytics' is prone to a
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"A malicious actor is able to inject malicious scripts, such as
  redirects, advertisements, and other HTML payloads into website.");

  script_tag(name:"affected", value:"WordPress Slimstat Analytics plugin prior to version 5.0.9.");

  script_tag(name:"solution", value:"Update to version 5.0.9 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/wp-slimstat/wordpress-slimstat-analytics-plugin-5-0-8-cross-site-scripting-xss-vulnerability");

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

if( version_is_less( version: version, test_version: "5.0.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.0.9", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

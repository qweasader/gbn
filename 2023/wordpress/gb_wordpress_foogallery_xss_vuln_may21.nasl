# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:fooplugins:foogallery";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127432");
  script_version("2023-05-19T09:09:15+0000");
  script_tag(name:"last_modification", value:"2023-05-19 09:09:15 +0000 (Fri, 19 May 2023)");
  script_tag(name:"creation_date", value:"2023-05-17 08:01:00 +0000 (Wed, 17 May 2023)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-18 01:11:00 +0000 (Fri, 18 Jun 2021)");

  script_cve_id("CVE-2021-24357");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress FooGallery Plugin < 2.0.35 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/foogallery/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'FooGallery' is prone to a
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"insight", value:"The Custom CSS field of each gallery is not properly sanitised
  or validated before being being output in the page where the gallery is embed.");

  script_tag(name:"affected", value:"WordPress FooGallery plugin prior to version 2.0.35.");

  script_tag(name:"solution", value:"Update to version 2.0.35 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/950f46ae-4476-4969-863a-0e55752953b3");

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

if( version_is_less( version: version, test_version: "2.0.35" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.0.35", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );

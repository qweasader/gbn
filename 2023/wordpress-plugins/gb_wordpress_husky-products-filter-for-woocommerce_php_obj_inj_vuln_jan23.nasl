# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:pluginus:husky_-_products_filter_professional_for_woocommerce";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127438");
  script_version("2023-12-28T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-12-28 05:05:25 +0000 (Thu, 28 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-05-23 07:42:09 +0000 (Tue, 23 May 2023)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-15 15:16:00 +0000 (Wed, 15 Feb 2023)");

  script_cve_id("CVE-2022-4489");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress HUSKY - Products Filter for WooCommerce Professional Plugin < 1.3.2 PHP Object Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/woocommerce-products-filter/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'HUSKY - Products Filter for WooCommerce
  Professional' is prone to a PHP object injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin unserializes user input provided via the settings,
  which could allow high privilege users such as admin to perform PHP Object Injection when a
  suitable gadget is present.");

  script_tag(name:"affected", value:"WordPress HUSKY - Products Filter for WooCommerce Professional
  prior to version 1.3.2.");

  script_tag(name:"solution", value:"Update to version 1.3.2 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/067573f2-b1e6-49a9-8c5b-f91e3b9d722f");

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

if( version_is_less( version: version, test_version: "1.3.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.3.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );

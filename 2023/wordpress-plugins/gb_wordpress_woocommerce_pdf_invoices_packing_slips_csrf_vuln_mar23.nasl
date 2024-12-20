# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:wpovernight:woocommerce_pdf_invoices%26_packing_slips";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126472");
  script_version("2024-06-27T05:05:29+0000");
  script_tag(name:"last_modification", value:"2024-06-27 05:05:29 +0000 (Thu, 27 Jun 2024)");
  script_tag(name:"creation_date", value:"2023-07-28 08:56:14 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-08 20:07:00 +0000 (Wed, 08 Mar 2023)");

  script_cve_id("CVE-2022-47148");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress WooCommerce PDF Invoices & Packing Slips Plugin < 3.2.6 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/woocommerce-pdf-invoices-packing-slips/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'WooCommerce PDF Invoices & Packing Slips'
  is prone to a cross-site request forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A malicious actor could force higher privileged users to
  execute unwanted actions under their current authentication.");

  script_tag(name:"affected", value:"WordPress WooCommerce PDF Invoices & Packing Slips plugin
  prior to version 3.2.6.");

  script_tag(name:"solution", value:"Update to version 3.2.6 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/woocommerce-pdf-invoices-packing-slips/wordpress-pdf-invoices-packing-slips-for-woocommerce-plugin-3-2-5-cross-site-request-forgery-csrf");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if ( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "3.2.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.2.6", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );

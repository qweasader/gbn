# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112887");
  script_version("2024-11-01T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"creation_date", value:"2021-04-26 12:11:11 +0000 (Mon, 26 Apr 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-29 20:51:00 +0000 (Thu, 29 Apr 2021)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2021-24241");

  script_name("WordPress Advanced Custom Fields Pro Plugin < 5.9.1 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/advanced-custom-fields-pro/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Advanced Custom Fields Pro' is prone
  to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not properly escape the generated update URL when
  outputting it in an attribute, leading to a reflected XSS issue in the update settings page.");

  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacker to
  inject arbitrary HTML and JavaScript into the site.");

  script_tag(name:"affected", value:"WordPress Advanced Custom Fields Pro through version 5.9.0.");

  script_tag(name:"solution", value:"Update to version 5.9.1 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/d1e9c995-37bd-4952-b88e-945e02e3c83f");
  script_xref(name:"URL", value:"https://www.advancedcustomfields.com/blog/acf-5-9-1-release/");
  script_xref(name:"URL", value:"https://github.com/jdordonezn/Reflected-XSS-in-WordPress-for-ACF-PRO-before-5.9.1-plugin/issues/1");

  exit(0);
}

CPE = "cpe:/a:advancedcustomfields:advanced_custom_fields_pro";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "5.9.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.9.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );

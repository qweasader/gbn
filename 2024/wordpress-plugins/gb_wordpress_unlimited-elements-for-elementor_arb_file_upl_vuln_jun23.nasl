# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:unlimited-elements:unlimited_elements_for_elementor_%28free_widgets%2c_addons%2c_templates%29";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127675");
  script_version("2024-10-31T05:05:48+0000");
  script_tag(name:"last_modification", value:"2024-10-31 05:05:48 +0000 (Thu, 31 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-01-04 08:20:45 +0000 (Thu, 04 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-27 20:21:00 +0000 (Wed, 27 Dec 2023)");

  script_cve_id("CVE-2023-31231");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Unlimited Elements For Elementor Plugin < 1.5.66 Arbitrary File Upload Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/unlimited-elements-for-elementor/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Unlimited Elements For Elementor' is
  prone to an arbitrary file upload vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Missing file type validation of files in the file manager
  functionality.");

  script_tag(name:"impact", value:"Authenticated attackers, with contributor-level permissions and
  above are able to upload arbitrary files on the affected site's server which may make remote code
  execution possible.");

  script_tag(name:"affected", value:"WordPress Unlimited Elements For Elementor plugin prior to
  version 1.5.66.");

  script_tag(name:"solution", value:"Update to version 1.5.66 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/unlimited-elements-for-elementor/wordpress-unlimited-elements-for-elementor-plugin-1-5-65-arbitrary-file-upload-vulnerability");

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

if( version_is_less( version: version, test_version: "1.5.66" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.5.66", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );

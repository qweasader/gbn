# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113559");
  script_version("2024-11-01T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"creation_date", value:"2019-11-11 10:41:14 +0000 (Mon, 11 Nov 2019)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-12 18:46:00 +0000 (Tue, 12 Nov 2019)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2019-17661");

  script_name("WordPress Admin Columns plugin <= 3.4.6 CSV Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/codepress-admin-columns/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Admin Columns' is prone to a CSV injection
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"By choosing formula code as his first or last name,
  an attacker can create users with names that contain malicious code.
  Other users might download this data as a CSV file and corrupt their PC
  by opening it in a tool such as Microsoft Excel.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to execute
  arbitrary code on the affected user's machine.");

  script_tag(name:"affected", value:"WordPress Admin Columns plugin through version 3.4.6.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_xref(name:"URL", value:"https://www2.deloitte.com/de/de/pages/risk/articles/wordpress-csv-injection.html");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/codepress-admin-columns/#developers");

  exit(0);
}

CPE = "cpe:/a:admincolumns:admin_columns";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "3.4.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None Available", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );

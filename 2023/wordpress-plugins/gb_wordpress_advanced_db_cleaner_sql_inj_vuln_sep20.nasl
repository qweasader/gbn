# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sigmaplugin:advanced_database_cleaner";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126411");
  script_version("2024-06-27T05:05:29+0000");
  script_tag(name:"last_modification", value:"2024-06-27 05:05:29 +0000 (Thu, 27 Jun 2024)");
  script_tag(name:"creation_date", value:"2023-06-14 09:15:11 +0000 (Wed, 14 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-22 19:45:00 +0000 (Mon, 22 Mar 2021)");

  script_cve_id("CVE-2021-24141");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Advanced Database Cleaner Plugin < 3.0.2 SQLi Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/advanced-database-cleaner/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Advanced Database Cleaner' is prone to an
  SQL injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin did not properly sanitise user input given, allowing
  high privilege users (admin+) to perform SQL injection attacks.");

  script_tag(name:"affected", value:"WordPress Advanced Database Cleaner prior to version 3.0.2.");

  script_tag(name:"solution", value:"Update to version 3.0.2 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/5c8adca0-fe19-4624-81ef-465b8d007f93");

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

if (version_is_less(version: version, test_version: "3.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit( 99 );

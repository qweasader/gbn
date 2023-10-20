# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:formidablepro2pdf:formidable_pro2pdf";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126519");
  script_version("2023-10-19T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-10-19 05:05:21 +0000 (Thu, 19 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-09-12 08:08:12 +0000 (Tue, 12 Sep 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-28 19:32:00 +0000 (Tue, 28 Mar 2023)");

  script_cve_id("CVE-2023-28663");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Formidable PRO2PDF Plugin < 3.10 SQL Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/formidablepro-2-pdf/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Formidable PRO2PDF' is prone to an SQL
  injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An authenticated SQL injection vulnerability in the 'fieldmap'
  parameter in the fpropdf_export_file action.");

  script_tag(name:"affected", value:"WordPress Formidable PRO2PDF plugin prior to version 3.10.");

  script_tag(name:"solution", value:"Update to version 3.10 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/formidablepro-2-pdf/formidable-pro2pdf-309-authenticated-admin-sql-injection");

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

if( version_is_less( version: version, test_version: "3.10" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.10", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );

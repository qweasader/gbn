# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:managewp:broken_link_checker";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126284");
  script_version("2024-11-01T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"creation_date", value:"2023-01-02 11:08:31 +0200 (Mon, 02 Jan 2023)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-06 20:00:00 +0000 (Fri, 06 Jan 2023)");

  script_cve_id("CVE-2022-3922");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Broken Link Checker Plugin < 1.11.20 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/broken-link-checker/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Broken Link Checker' is prone to a
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not sanitise and escape some of its settings,
  which could allow high privilege users such as admin to perform stored XSS attacks even when the
  unfiltered_html capability is disallowed.");

  script_tag(name:"affected", value:"WordPress Broken Link Checker plugin prior to version 1.11.20.");

  script_tag(name:"solution", value:"Update to version 1.11.20 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/78054bd7-cdc2-4b14-9b5c-30f10e802d6b");

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

if( version_is_less( version: version, test_version: "1.11.20" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.11.20", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );

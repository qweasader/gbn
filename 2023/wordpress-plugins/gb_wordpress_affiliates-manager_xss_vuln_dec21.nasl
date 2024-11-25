# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wpaffiliatemanager:affiliates_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170311");
  script_version("2024-11-01T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"creation_date", value:"2023-02-17 19:58:20 +0000 (Fri, 17 Feb 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-28 16:26:00 +0000 (Fri, 28 Jan 2022)");

  script_cve_id("CVE-2021-25078");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Affiliates Manager Plugin < 2.9.0 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/affiliates-manager/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Affiliates Manager' is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not validate, sanitise and escape the IP address
  of requests logged by the click tracking feature, allowing unauthenticated attackers to perform
  XSS attacks against admin viewing the tracked requests.");

  script_tag(name:"affected", value:"WordPress Affiliates Manager plugin prior to version 2.9.0.");

  script_tag(name:"solution", value:"Update to version 2.9.0.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/d4edb5f2-aa1b-4e2d-abb4-76c46def6c6e");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"2.9.0" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"2.9.0", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

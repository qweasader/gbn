# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:codecabin:wp_go_maps";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112552");
  script_version("2023-05-30T09:08:51+0000");
  script_tag(name:"last_modification", value:"2023-05-30 09:08:51 +0000 (Tue, 30 May 2023)");
  script_tag(name:"creation_date", value:"2019-03-28 23:58:11 +0100 (Thu, 28 Mar 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-26 15:00:00 +0000 (Fri, 26 May 2023)");

  script_cve_id("CVE-2019-9912");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Google Maps Plugin < 7.10.43 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-google-maps/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Google Maps' is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to inject
  malicious content into an affected site.");

  script_tag(name:"affected", value:"WordPress Google Maps plugin before version 7.10.43.");

  script_tag(name:"solution", value:"Update to version 7.10.43 or later.");

  script_xref(name:"URL", value:"https://lists.openwall.net/full-disclosure/2019/02/05/13");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/wp-google-maps/#developers");

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

if( version_is_less( version: version, test_version: "7.10.43" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.10.43", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );

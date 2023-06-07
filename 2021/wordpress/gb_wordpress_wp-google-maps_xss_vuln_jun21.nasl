# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:codecabin:wp_go_maps";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146812");
  script_version("2023-05-26T09:09:36+0000");
  script_tag(name:"last_modification", value:"2023-05-26 09:09:36 +0000 (Fri, 26 May 2023)");
  script_tag(name:"creation_date", value:"2021-09-30 09:56:19 +0000 (Thu, 30 Sep 2021)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-17 19:51:00 +0000 (Fri, 17 Sep 2021)");

  script_cve_id("CVE-2021-36870");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Google Maps Plugin < 8.1.13 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-google-maps/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Google Maps' is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"WordPress Google Maps plugin version 8.1.12 and prior.");

  script_tag(name:"solution", value:"Update to version 8.1.13 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/wp-google-maps/wordpress-wp-google-maps-plugin-8-1-12-multiple-authenticated-persistent-cross-site-scripting-xss-vulnerabilities");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/wp-google-maps/#developers");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "8.1.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.1.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
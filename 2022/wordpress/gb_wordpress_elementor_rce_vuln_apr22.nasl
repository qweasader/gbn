# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:elementor:website_builder";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124062");
  script_version("2023-05-25T09:08:46+0000");
  script_tag(name:"last_modification", value:"2023-05-25 09:08:46 +0000 (Thu, 25 May 2023)");
  script_tag(name:"creation_date", value:"2022-04-27 18:22:38 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Elementor Page Builder Plugin 3.6.x < 3.6.4 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/elementor/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Elementor Page Builder' is prone to a remote
  code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The RCE vulnerability involves the function
  upload_and_install_pro() accessible through the previous function.");

  script_tag(name:"affected", value:"WordPress Elementor Page Builder plugin versions 3.6.x prior to
  3.6.4.");

  script_tag(name:"solution", value:"Update to version 3.6.4 or later.");

  script_xref(name:"URL", value:"https://www.pluginvulnerabilities.com/2022/04/12/5-million-install-wordpress-plugin-elementor-contains-authenticated-remote-code-execution-rce-vulnerability/");

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

if (version_in_range_exclusive(version: version, test_version_lo: "3.6.0", test_version_up: "3.6.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.6.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

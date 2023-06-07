# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:rankmath:seo";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127181");
  script_version("2023-05-26T09:09:36+0000");
  script_tag(name:"last_modification", value:"2023-05-26 09:09:36 +0000 (Fri, 26 May 2023)");
  script_tag(name:"creation_date", value:"2022-09-12 06:49:12 +0000 (Mon, 12 Sep 2022)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2022-36376");

  script_name("WordPress Rank Math SEO Plugin < 1.0.95.1 SSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/seo-by-rank-math/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'SEO by Rank Math' is prone to server-side
  request forgery (SSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Public REST endpoints blocked via .htaccess file are accessible
  through Headless endpoint, when that option is active.");

  script_tag(name:"affected", value:"WordPress SEO by Rank Math plugin prior to version 1.0.95.1.");

  script_tag(name:"solution", value:"Update to version 1.0.95.1 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/seo-by-rank-math/wordpress-rank-math-seo-plugin-1-0-95-server-side-request-forgery-ssrf-vulnerability/");

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

if (version_is_less(version: version, test_version: "1.0.95.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.0.95.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

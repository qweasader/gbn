# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:litespeedtech:litespeed_cache";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124330");
  script_version("2023-06-01T09:09:48+0000");
  script_tag(name:"last_modification", value:"2023-06-01 09:09:48 +0000 (Thu, 01 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-05-29 07:31:32 +0000 (Mon, 29 May 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");

  script_cve_id("CVE-2022-46800");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress LiteSpeed Cache Plugin < 5.3.1 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/litespeed-cache/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'LiteSpeed Cache' is prone to a cross-site
  request forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An CSRF vulnerability could allow a malicious actor to force
  higher privileged users to execute unwanted actions under their current authentication.");

  script_tag(name:"affected", value:"WordPress LiteSpeed Cache plugin prior to version 5.3.1.");

  script_tag(name:"solution", value:"Update to version 5.3.1 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/litespeed-cache/wordpress-litespeed-cache-plugin-5-3-cross-site-request-forgery-csrf-vulnerability?_s_id=cve");

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

if (version_is_less(version: version, test_version: "5.3.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

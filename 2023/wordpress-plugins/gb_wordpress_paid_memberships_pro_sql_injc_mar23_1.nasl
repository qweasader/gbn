# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:paidmembershipspro:paid_memberships_pro";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126006");
  script_version("2024-11-08T15:39:48+0000");
  script_tag(name:"last_modification", value:"2024-11-08 15:39:48 +0000 (Fri, 08 Nov 2024)");
  script_tag(name:"creation_date", value:"2023-01-23 08:15:45 +0000 (Mon, 23 Jan 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-23 19:05:00 +0000 (Thu, 23 Mar 2023)");

  script_cve_id("CVE-2023-0631");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Paid Memberships Pro Plugin < 2.9.12 SQLi Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/paid-memberships-pro/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Paid Memberships Pro' is prone to an SQL
  injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not prevent subscribers from rendering
  shortcodes that concatenate attributes directly into an SQL query.");

  script_tag(name:"affected", value:"WordPress Paid Memberships Pro prior to version 2.9.12.");

  script_tag(name:"solution", value:"Update to version 2.9.12 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/19ef92fd-b493-4488-91f0-e6ba51362f79");

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

if (version_is_less(version: version, test_version: "2.9.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.9.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wpdownloadmanager:wordpress_download_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127176");
  script_version("2023-10-19T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-10-19 05:05:21 +0000 (Thu, 19 Oct 2023)");
  script_tag(name:"creation_date", value:"2022-09-07 11:11:02 +0000 (Wed, 07 Sep 2022)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-09 03:12:00 +0000 (Fri, 09 Sep 2022)");

  script_cve_id("CVE-2022-2431");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Download Manager Plugin < 3.2.51 Arbitrary File Deletion Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/download-manager/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Download Manager' is prone to an
  arbitrary file deletion vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin allows an authenticated attacker to delete arbitrary
  files hosted on the server, provided they have access to create downloads.");

  script_tag(name:"affected", value:"WordPress Download Manager plugin prior to version 3.2.51.");

  script_tag(name:"solution", value:"Update to version 3.2.51 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2022/08/high-severity-vulnerability-patched-in-download-manager-plugin/");

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

if (version_is_less(version: version, test_version: "3.2.51")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.51", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

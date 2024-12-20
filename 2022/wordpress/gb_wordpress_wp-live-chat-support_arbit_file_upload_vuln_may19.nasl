# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:3cx:live_chat";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127109");
  script_version("2023-06-13T05:04:52+0000");
  script_tag(name:"last_modification", value:"2023-06-13 05:04:52 +0000 (Tue, 13 Jun 2023)");
  script_tag(name:"creation_date", value:"2022-07-29 13:40:08 +0000 (Fri, 29 Jul 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-04 20:42:00 +0000 (Tue, 04 Jun 2019)");

  script_cve_id("CVE-2019-11185");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Live Chat Support Plugin < 8.0.26 Arbitrary File Upload Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-live-chat-support/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Live Chat Support' is prone to an
  arbitrary file upload vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin allows an unauthenticated remote user to submit a
  crafted file upload POST request to the REST API remote_upload endpoint.");

  script_tag(name:"affected", value:"WordPress Live Chat Support plugin prior to version 8.0.32.");

  script_tag(name:"solution", value:"Update to version 8.0.32 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/9320");


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

if (version_is_less(version: version, test_version: "8.0.32")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.32", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

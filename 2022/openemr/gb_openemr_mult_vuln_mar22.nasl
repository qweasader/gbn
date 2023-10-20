# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:open-emr:openemr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124048");
  script_version("2023-10-19T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-10-19 05:05:21 +0000 (Thu, 19 Oct 2023)");
  script_tag(name:"creation_date", value:"2022-03-30 17:04:08 +0000 (Wed, 30 Mar 2022)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-29 18:26:00 +0000 (Tue, 29 Mar 2022)");

  script_cve_id("CVE-2022-24643", "CVE-2022-25041");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenEMR <= 6.0.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_openemr_detect.nasl");
  script_mandatory_keys("openemr/installed");

  script_tag(name:"summary", value:"OpenEMR is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-24643: Cross-site scripting (XSS)

  - CVE-2022-25041: Incorrect access control");

  script_tag(name:"affected", value:"OpenEMR version 6.0.0 and prior.");

  script_tag(name:"solution", value:"Update to version 7.0.0 or later.");

  script_xref(name:"URL", value:"https://securityforeveryone.com/blog/openemr-0-day-stored-cross-site-scripting-xss-vulnerability-cve-2022-24643");
  script_xref(name:"URL", value:"https://securityforeveryone.com/blog/openemr-0-day-incorrect-access-control-vulnerability-cve-2022-25041");
  script_xref(name:"URL", value:"https://github.com/openemr/openemr/commit/ef4a62e68d5c5563fa5b9624508c76c0c50bb792");
  script_xref(name:"URL", value:"https://github.com/openemr/openemr/commit/619db1d7d7bf5e6a31e7d0489c068998bc9e9327");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "7.0.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);

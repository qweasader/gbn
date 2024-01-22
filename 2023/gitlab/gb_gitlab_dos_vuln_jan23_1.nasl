# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:gitlab:gitlab";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124268");
  script_version("2023-12-06T05:06:11+0000");
  script_tag(name:"last_modification", value:"2023-12-06 05:06:11 +0000 (Wed, 06 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-02-03 09:58:27 +0000 (Fri, 03 Feb 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-27 17:30:00 +0000 (Mon, 27 Feb 2023)");

  script_cve_id("CVE-2022-3411");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("GitLab 12.4.x < 15.6.7, 15.7.x < 15.7.6, 15.8.x < 15.8.1 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_gitlab_consolidation.nasl");
  script_mandatory_keys("gitlab/detected");

  script_tag(name:"summary", value:"GitLab is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A lack of length validation allows an authenticated attacker to
  create a large Issue description via GraphQL which, when repeatedly requested, saturates CPU
  usage.");

  script_tag(name:"affected", value:"GitLab versions 12.4.x prior to 15.6.7, 15.7.x prior to 15.7.6
  and 15.8.x prior to 15.8.1.");

  script_tag(name:"solution", value:"Update to version 15.6.7, 15.7.6, 15.8.1 or later.");

  script_xref(name:"URL", value:"https://about.gitlab.com/releases/2023/01/31/security-release-gitlab-15-8-1-released/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "12.4.0", test_version_up: "15.6.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "15.6.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "15.7.0", test_version_up: "15.7.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "15.7.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "15.8.0", test_version_up: "15.8.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "15.8.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

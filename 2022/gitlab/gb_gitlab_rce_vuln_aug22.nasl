# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:gitlab:gitlab";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104302");
  script_version("2023-12-06T05:06:11+0000");
  script_tag(name:"last_modification", value:"2023-12-06 05:06:11 +0000 (Wed, 06 Dec 2023)");
  script_tag(name:"creation_date", value:"2022-08-24 13:11:50 +0000 (Wed, 24 Aug 2022)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-19 17:48:00 +0000 (Wed, 19 Oct 2022)");

  script_cve_id("CVE-2022-2884");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("GitLab 11.3.4 < 15.1.5, 15.2.x < 15.2.3, 15.3.x < 15.3.1 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_gitlab_consolidation.nasl");
  script_mandatory_keys("gitlab/detected");

  script_tag(name:"summary", value:"GitLab is prone to a remote command execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability allows an authenticated user to achieve remote
  code execution via the Import from GitHub API endpoint.");

  script_tag(name:"affected", value:"GitLab versions starting from 11.3.4 before 15.1.5, all
  versions starting from 15.2 before 15.2.3, all versions starting from 15.3 before 15.3.1.");

  script_tag(name:"solution", value:"Update to version 15.1.5, 15.2.3, 15.3.1 or later.

  A possible workaround to disable the GitHub import is provided by the vendor in the referenced
  advisory.");

  script_xref(name:"URL", value:"https://about.gitlab.com/releases/2022/08/22/critical-security-release-gitlab-15-3-1-released/");
  script_xref(name:"URL", value:"https://gitlab.com/gitlab-org/cves/-/blob/master/2022/CVE-2022-2884.json");

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

if (version_in_range_exclusive(version: version, test_version_lo: "11.3.4", test_version_up: "15.1.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "15.1.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "15.2.0", test_version_up: "15.2.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "15.2.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "15.3.0", test_version_up: "15.3.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "15.3.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

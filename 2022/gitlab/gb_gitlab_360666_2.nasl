# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:gitlab:gitlab";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124113");
  script_version("2023-12-06T05:06:11+0000");
  script_tag(name:"last_modification", value:"2023-12-06 05:06:11 +0000 (Wed, 06 Dec 2023)");
  script_tag(name:"creation_date", value:"2022-07-08 09:47:46 +0000 (Fri, 08 Jul 2022)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-13 18:24:00 +0000 (Wed, 13 Jul 2022)");

  script_cve_id("CVE-2022-2244");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("GitLab 14.8.x < 14.10.5, 15.0.x < 15.0.4, 15.1.x < 15.1.1 Improper Authorization Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_gitlab_consolidation.nasl");
  script_mandatory_keys("gitlab/detected");

  script_tag(name:"summary", value:"GitLab is prone to an improper authorization vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"GitLab allows project members with reporter role to manage
  issues in project's error tracking feature.");

  script_tag(name:"affected", value:"GitLab version 14.8.x through 14.10.4, 15.0.x through 15.0.3
  and 15.1.0.");

  script_tag(name:"solution", value:"Update to version 14.10.5, 15.0.4, 15.1.1 or later.");

  script_xref(name:"URL", value:"https://gitlab.com/gitlab-org/cves/-/blob/master/2022/CVE-2022-2244.json");

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

if (version_in_range_exclusive(version: version, test_version_lo: "14.8", test_version_up: "14.10.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.10.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "15.0", test_version_up: "15.0.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "15.0.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "15.1", test_version_up: "15.1.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "15.1.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
